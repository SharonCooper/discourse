# frozen_string_literal: true

class SecondFactor::AuthManager
  class SecondFactorRequired < StandardError
    attr_reader :nonce

    def initialize(nonce:)
      @nonce = nonce
    end
  end

  attr_reader :allowed_methods

  def initialize(current_user, guardian, action)
    @current_user = current_user
    @guardian = guardian
    @action = action
    @allowed_methods = Set.new([
      UserSecondFactor.methods[:totp],
      UserSecondFactor.methods[:security_key],
    ]).freeze
  end

  def allow_backup_codes!
    add_method(UserSecondFactor.methods[:backup_codes])
  end

  def run!(request, params, secure_session)
    if !allowed_methods.any? { |m| @current_user.valid_second_factor_method_for_user?(m) }
      @action.no_second_factors_enabled!(params)
      create_result(:no_second_factor)
    elsif nonce = params[:second_factor_nonce].presence
      verify_second_factor_auth(nonce, secure_session)
      create_result(:second_factor_auth_successful)
    else
      nonce = initiate_second_factor_auth(params, secure_session, request)
      raise SecondFactorRequired.new(nonce: nonce)
    end
  end

  private

  def initiate_second_factor_auth(params, secure_session, request)
    config = @action.second_factor_auth_required!(params)
    nonce = SecureRandom.alphanumeric(32)
    callback_params = config[:callback_params] || {}
    redirect_path = config[:redirect_path] || GlobalPath.path("/")
    challenge = {
      nonce: nonce,
      callback_method: request.method,
      callback_path: request.path,
      callback_params: callback_params,
      redirect_path: redirect_path,
      allowed_methods: allowed_methods.to_a
    }
    secure_session.set(
      "current_second_factor_auth_challenge",
      challenge.to_json,
      expires: 5.minutes
    )
    nonce
  end

  def verify_second_factor_auth(nonce, secure_session)
    json = secure_session["current_second_factor_auth_challenge"]
    raise Discourse::InvalidAccess.new if json.blank?

    challenge = JSON.parse(json).deep_symbolize_keys
    if challenge[:nonce] != nonce
      raise Discourse::InvalidAccess.new
    end
    if !challenge[:successful]
      raise Discourse::InvalidAccess.new
    end
    secure_session["current_second_factor_auth_challenge"] = nil
    callback_params = challenge[:callback_params]
    @action.second_factor_auth_successful!(callback_params)
  end

  def add_method(id)
    if !@allowed_methods.include?(id)
      @allowed_methods = Set.new(@allowed_methods)
      @allowed_methods.add(id)
      @allowed_methods.freeze
    end
  end

  def create_result(status)
    SecondFactor::AuthManagerResult.new(status)
  end
end
