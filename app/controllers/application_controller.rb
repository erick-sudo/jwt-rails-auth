class ApplicationController < ActionController::API
    wrap_parameters format: []
    rescue_from ActiveRecord::RecordInvalid, with: :record_invalid_response
    rescue_from ActiveRecord::RecordNotFound, with: :record_not_found_response

    before_action :authorized

    def encode_token(payload)
        # payload => { beef: 'steak' }
        JWT.encode(payload, 'mysecret')
        # jwt string: "eyJhbGciOiJIUzI1NiJ9.eyJiZWVmIjoic3RlYWsifQ._IBTHTLGX35ZJWTCcY30tLmwU9arwdpNVxtVU0NpAuI"
    end

    # def decode_token(token)
    #     # token => "eyJhbGciOiJIUzI1NiJ9.eyJiZWVmIjoic3RlYWsifQ._IBTHTLGX35ZJWTCcY30tLmwU9arwdpNVxtVU0NpAuI"

    #     JWT.decode(token, 'mysecret')[0]
    #     # JWT.decode => [{ "beef"=>"steak" }, { "alg"=>"HS256" }]
    #     # [0] gives us the payload { "beef"=>"steak" }
    # end

    def auth_header
      # { Authorization: 'Bearer <token>' }
      request.headers['Authorization']
    end

    def decoded_token
        if auth_header
          token = auth_header.split(' ')[1]
          # header: { 'Authorization': 'Bearer <token>' }
          begin
            JWT.decode(token, 'mysecret', true, algorithm: 'HS256')
          rescue JWT::DecodeError
            nil
          end
        end
    end

    def current_user
        if decoded_token
          # decoded_token=> [{"user_id"=>2}, {"alg"=>"HS256"}]
          # or nil if we can't decode the token
          user_id = decoded_token[0]['user_id']
          @user = User.find_by(id: user_id)
        end
    end

    def logged_in?
        !!current_user
    end

    def authorized
        render json: { message: 'Please log in' }, status: :unauthorized unless logged_in?
    end

  private

  def record_invalid_response(invalid)
    render json: { errors: invalid.record.errors.full_messages }, status: :unprocessable_entity
  end

  def record_not_found_response
    render json: { error: "#{controller_name.classify} not found" },status: :not_found
  end
end
