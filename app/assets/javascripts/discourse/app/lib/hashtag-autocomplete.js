import { findRawTemplate } from "discourse-common/lib/raw-templates";
import domFromString from "discourse-common/lib/dom-from-string";
import discourseLater from "discourse-common/lib/later";
import { INPUT_DELAY, isTesting } from "discourse-common/config/environment";
import { cancel } from "@ember/runloop";
import { CANCELLED_STATUS } from "discourse/lib/autocomplete";
import { ajax } from "discourse/lib/ajax";
import discourseDebounce from "discourse-common/lib/debounce";
import {
  caretPosition,
  escapeExpression,
  inCodeBlock,
} from "discourse/lib/utilities";
import { emojiUnescape } from "discourse/lib/text";
import { htmlSafe } from "@ember/template";

let hashtagTypeClasses = {};
export function registerHashtagType(type, typeClassInstance) {
  hashtagTypeClasses[type] = typeClassInstance;
}
export function cleanUpHashtagTypeClasses() {
  hashtagTypeClasses = {};
}
export function getHashtagTypeClasses() {
  return hashtagTypeClasses;
}
export function decorateHashtags(element, site) {
  element.querySelectorAll(".hashtag-cooked").forEach((hashtagEl) => {
    // Replace the empty icon placeholder span with actual icon HTML.
    const iconPlaceholderEl = hashtagEl.querySelector(
      ".hashtag-icon-placeholder"
    );
    const hashtagType = hashtagEl.dataset.type;
    const hashtagTypeClass = getHashtagTypeClasses()[hashtagType];
    if (iconPlaceholderEl && hashtagTypeClass) {
      const hashtagIconHTML = hashtagTypeClass
        .generateIconHTML({
          icon: site.hashtag_icons[hashtagType],
          id: hashtagEl.dataset.id,
        })
        .trim();
      iconPlaceholderEl.replaceWith(domFromString(hashtagIconHTML)[0]);
    }

    // Add an aria-label to the hashtag element so that screen readers
    // can read the hashtag text.
    hashtagEl.setAttribute("aria-label", `${hashtagEl.innerText.trim()}`);
  });
}

export function generatePlaceholderHashtagHTML(type, spanEl, data) {
  // NOTE: When changing the HTML structure here, you must also change
  // it in the hashtag-autocomplete markdown rule, and vice-versa.
  const link = document.createElement("a");
  link.classList.add("hashtag-cooked");
  link.href = data.relative_url;
  link.dataset.type = type;
  link.dataset.id = data.id;
  link.dataset.slug = data.slug;
  const hashtagTypeClass = new getHashtagTypeClasses()[type];
  link.innerHTML = `${hashtagTypeClass.generateIconHTML(
    data
  )}<span>${emojiUnescape(data.text)}</span>`;
  spanEl.replaceWith(link);
}

/**
 * Sets up a textarea using the jQuery autocomplete plugin, specifically
 * to match on the hashtag (#) character for autocompletion of categories,
 * tags, and other resource data types.
 *
 * @param {Array} contextualHashtagConfiguration - The hashtag datasource types in priority order
 *   that should be used when searching for or looking up hashtags from the server, determines
 *   the order of search results and the priority for looking up conflicting hashtags. See also
 *   Site.hashtag_configurations.
 * @param {$Element} $textarea - jQuery element to use for the autocompletion
 *   plugin to attach to, this is what will watch for the # matcher when the user is typing.
 * @param {Hash} siteSettings - The clientside site settings.
 * @param {Function} autocompleteOptions - Options to pass to the jQuery plugin. Must at least include:
 *
 *  - afterComplete - Called with the selected autocomplete option once it is selected.
 *
 *  Can also include:
 *
 *  - treatAsTextarea - Whether to anchor the autocompletion to the start of the input and
 *                      ensure the popper is always on top.
 **/
export function setupHashtagAutocomplete(
  contextualHashtagConfiguration,
  $textArea,
  siteSettings,
  autocompleteOptions = {}
) {
  _setup(
    contextualHashtagConfiguration,
    $textArea,
    siteSettings,
    autocompleteOptions
  );
}

export function hashtagTriggerRule(textarea) {
  if (inCodeBlock(textarea.value, caretPosition(textarea))) {
    return false;
  }

  return true;
}

const checkedHashtags = new Set();
let seenHashtags = {};

// NOTE: For future maintainers, the hashtag lookup here does not take
// into account mixed contexts -- for instance, a chat quote inside a post
// or a post quote inside a chat message, so this may
// not provide an accurate priority lookup for hashtags without a ::type suffix in those
// cases.
export function fetchUnseenHashtagsInContext(
  contextualHashtagConfiguration,
  slugs
) {
  return ajax("/hashtags", {
    data: { slugs, order: contextualHashtagConfiguration },
  }).then((response) => {
    Object.keys(response).forEach((type) => {
      seenHashtags[type] = seenHashtags[type] || {};
      response[type].forEach((item) => {
        seenHashtags[type][item.ref] = seenHashtags[type][item.ref] || item;
      });
    });
    slugs.forEach(checkedHashtags.add, checkedHashtags);
  });
}

export function linkSeenHashtagsInContext(
  contextualHashtagConfiguration,
  elem
) {
  const hashtagSpans = [...(elem?.querySelectorAll("span.hashtag-raw") || [])];
  if (hashtagSpans.length === 0) {
    return [];
  }
  const slugs = [
    ...hashtagSpans.map((span) => span.innerText.replace("#", "")),
  ];

  hashtagSpans.forEach((hashtagSpan, index) => {
    _findAndReplaceSeenHashtagPlaceholder(
      slugs[index],
      contextualHashtagConfiguration,
      hashtagSpan
    );
  });

  return slugs
    .map((slug) => slug.toLowerCase())
    .uniq()
    .filter((slug) => !checkedHashtags.has(slug));
}

function _setup(
  contextualHashtagConfiguration,
  $textArea,
  siteSettings,
  autocompleteOptions
) {
  $textArea.autocomplete({
    template: findRawTemplate("hashtag-autocomplete"),
    key: "#",
    afterComplete: autocompleteOptions.afterComplete,
    treatAsTextarea: autocompleteOptions.treatAsTextarea,
    scrollElementSelector: ".hashtag-autocomplete__fadeout",
    autoSelectFirstSuggestion: true,
    transformComplete: (obj) => obj.ref,
    dataSource: (term) => {
      if (term.match(/\s/)) {
        return null;
      }
      return _searchGeneric(term, siteSettings, contextualHashtagConfiguration);
    },
    triggerRule: (textarea, opts) => hashtagTriggerRule(textarea, opts),
  });
}

let searchCache = {};
let searchCacheTime;
let currentSearch;

function _updateSearchCache(term, results) {
  searchCache[term] = results;
  searchCacheTime = new Date();
  return results;
}

// Note that the search term is _not_ required here, and we follow special
// logic similar to @mentions when there is no search term, to show some
// useful default categories, tags, etc.
function _searchGeneric(term, siteSettings, contextualHashtagConfiguration) {
  if (currentSearch) {
    currentSearch.abort();
    currentSearch = null;
  }
  if (new Date() - searchCacheTime > 30000) {
    searchCache = {};
  }
  const cached = searchCache[term];
  if (cached) {
    return cached;
  }

  return new Promise((resolve) => {
    let timeoutPromise = isTesting()
      ? null
      : discourseLater(() => {
          resolve(CANCELLED_STATUS);
        }, 5000);

    const debouncedSearch = (q, ctx, resultFunc) => {
      discourseDebounce(this, _searchRequest, q, ctx, resultFunc, INPUT_DELAY);
    };

    debouncedSearch(term, contextualHashtagConfiguration, (result) => {
      cancel(timeoutPromise);
      resolve(_updateSearchCache(term, result));
    });
  });
}

function _searchRequest(term, contextualHashtagConfiguration, resultFunc) {
  currentSearch = ajax("/hashtags/search.json", {
    data: { term, order: contextualHashtagConfiguration },
  });
  currentSearch
    .then((response) => {
      response.results?.forEach((result) => {
        // Convert :emoji: in the result text to HTML safely.
        result.text = htmlSafe(emojiUnescape(escapeExpression(result.text)));

        const hashtagType = getHashtagTypeClasses()[result.type];
        result.icon = hashtagType.generateIconHTML({
          icon: result.icon,
          id: result.id,
        });
      });
      resultFunc(response.results || CANCELLED_STATUS);
    })
    .finally(() => {
      currentSearch = null;
    });
  return currentSearch;
}

function _findAndReplaceSeenHashtagPlaceholder(
  slugRef,
  contextualHashtagConfiguration,
  hashtagSpan
) {
  contextualHashtagConfiguration.forEach((type) => {
    // Replace raw span for the hashtag with a cooked one
    const matchingSeenHashtag = seenHashtags[type]?.[slugRef];
    if (matchingSeenHashtag) {
      generatePlaceholderHashtagHTML(type, hashtagSpan, matchingSeenHashtag);
    }
  });
}
