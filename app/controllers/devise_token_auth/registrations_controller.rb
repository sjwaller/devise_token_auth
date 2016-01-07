module DeviseTokenAuth
  class RegistrationsController < DeviseTokenAuth::ApplicationController
    before_filter :set_user_by_token, :only => [:destroy, :update]
    skip_after_filter :update_auth_header, :only => [:create, :destroy]

    respond_to :json

    def create
      @resource            = resource_class.new(sign_up_params)
      @resource.uid        = sign_up_params[:email]
      @resource.provider   = "email"

      # success redirect url is required
      unless params[:confirm_success_url]
        return render json: {
          status: 'error',
          data:   @resource,
          errors: ["Missing `confirm_success_url` param."]
        }, status: 403
      end

      begin
        # override email confirmation, must be sent manually from ctrl
        @resource.class.skip_callback("create", :after, :send_on_create_confirmation_instructions)
        if @resource.save

          unless @resource.confirmed?
            # user will require email authentication
            @resource.send_confirmation_instructions({
              client_config: params[:config_name],
              redirect_url: params[:confirm_success_url]
            })

          else
            # email auth has been bypassed, authenticate user
            @client_id = SecureRandom.urlsafe_base64(nil, false)
            @token     = SecureRandom.urlsafe_base64(nil, false)

            @resource.tokens[@client_id] = {
              token: BCrypt::Password.create(@token),
              expiry: (Time.now + DeviseTokenAuth.token_lifespan).to_i
            }

            @resource.save!

            update_auth_header
          end
          render_create_success
        else
          clean_up_passwords @resource
          render_create_error
        end

      rescue Mongo::Error::OperationFailure => e
        description = e.details['err']
        if [11000, 11001].include?(e.details['code'])
          clean_up_passwords @resource
          render_create_error_email_already_exists
        else
          raise
        end
      end
    end
    
    def update
      if @resource
        if @resource.update_attributes(account_update_params)
          render_update_success
        else
          render_update_error
        end
      else
        render_update_error_user_not_found
      end
    end

    def destroy
      if @resource
        @resource.destroy
        render_destroy_success
      else
        render_destroy_error
      end
    end

    def sign_up_params
      params.permit(devise_parameter_sanitizer.for(:sign_up))
    end

    def account_update_params
      params.permit(devise_parameter_sanitizer.for(:account_update))
    end
    
    protected
      
    def render_create_success
      render json: {
        status: 'success',
        data:   @resource.as_json
      }
    end

    def render_create_error
      render json: {
        status: 'error',
        data:   @resource.as_json,
        errors: @resource.errors.to_hash.merge(full_messages: @resource.errors.full_messages)
      }, status: 403
    end
    
    def render_create_error_email_already_exists
      render json: {
        status: 'error',
        data:   @resource.as_json,
        errors: ["An account already exists for #{@resource.email}"]
      }, status: 403
    end  
    
    def render_update_success
      render json: {
        status: 'success',
        data:   @resource.as_json
      }
    end
    
    def render_update_error
      render json: {
        status: 'error',
        errors: @resource.errors.to_hash.merge(full_messages: @resource.errors.full_messages)
      }, status: 403
    end
    
    def render_update_error_user_not_found
      render json: {
        status: 'error',
        errors: ["User not found"]
      }, status: 404
    end
 
    def render_destroy_success
      render json: {
        status: 'success',
        message: "Account with uid #{@resource.uid} has been destroyed."
      }
    end

    def render_destroy_error
      render json: {
        status: 'error',
        errors: ["Unable to locate account for destruction."]
      }, status: 404
    end   

  end
end
