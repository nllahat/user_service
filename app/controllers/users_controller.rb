# Users controller
class UsersController < ApplicationController
  protect_from_forgery with: :null_session
  skip_before_action :verify_authenticity_token
  before_action :find_user_by_cookies, only: %i[index show update sign_out]
  before_action :id_match_current_user, only: %i[show update]
  before_action :find_user_by_email, only: :sign_in

  # GET /users
  def index
    users = User.all
    users = users.map { |user| parse_user(user) }
    json_response('Fetch all users', true, users, :ok)
  end

  # GET /users/1
  def show
    render json: parse_user(@user)
  end

  # PUT /users/1
  def update
    if @user
      @user.update(user_params_update)
      json_response('Update successfully', true, parse_user(@user), :no_content)
    else
      # 404
      json_response('User not found', false, {}, :not_found)
    end
  end

  # POST /sign_up
  def sign_up
    user = User.new(
      first_name: user_params_registration[:first_name],
      last_name: user_params_registration[:last_name],
      email: user_params_registration[:email],
      encrypted_password: BCrypt::Password.create(user_params_registration[:password])
    )

    if user_params_registration[:password_confirmation] != user_params_registration[:password]
      json_response('Passwords match error', false, {}, :bad_request)
    elsif user.save
      json_response('Signed up successfully', true, parse_user(user), :created)
    else
      json_response('Error on signup', false, {}, :bad_request)
    end
  end

  def sign_in
    if !@user
      json_response('User not found', false, {}, :not_found)
    elsif !BCrypt::Password.new(@user.encrypted_password).is_password?(params_sign_in[:password])
      json_response('Wrong email or password', false, {}, :unauthorized)
    else
      update_token
      json_response('Signed in successfully', true, parse_user(@user), :ok)
    end
  end

  def sign_out
    if !@user
      json_response('User not found', false, {}, :not_found)
    else
      @user.update(authentication_token: nil)
      cookies.clear
      json_response('Signed out successfully', true, {}, :ok)
    end
  end

  private

  def find_user_by_id
    @user = User.find(params[:id])
  end

  def find_user_by_email
    @user = User.find_by(email: params_sign_in[:email])
  end

  def find_user_by_cookies
    @user = User.find_by(authentication_token: cookies[:token])
  end

  def update_token
    @user.update(authentication_token: SecureRandom.base64)
    cookies[:token] = @user.authentication_token
  end

  # Only allow a trusted parameter "white list" through.
  def user_params_update
    params.require(:user).permit(:first_name, :last_name)
  end

  # Only allow a trusted parameter "white list" through.
  def user_params_registration
    params.require(:user).permit(
      :first_name,
      :last_name,
      :email,
      :password,
      :password_confirmation
    )
  end

  def params_sign_in
    params.require(:sign_in).permit(:email, :password)
  end

  def parse_user(user)
    {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email
    }
  end

  def json_response(messages, is_success, data, status)
    render json: { messages: messages, is_success: is_success, data: data },
           status: status
  end

  # get only logged in user
  def id_match_current_user
    return if @user.id.to_s == params[:id]

    json_response('Forbidden', false, {}, :forbidden)
  end
end
