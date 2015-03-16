module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class WorldpayOnlinePaymentsGateway < Gateway
      self.live_url =  'https://api.worldpay.com/v1/'

      self.default_currency = 'GBP'

      self.money_format = :cents

      self.supported_countries = %w(HK US GB AU AD BE CH CY CZ DE DK ES FI FR GI GR HU IE IL IT LI LU MC MT NL NO NZ PL PT SE SG SI SM TR UM VA)
      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :jcb, :maestro, :laser, :switch]

      self.homepage_url = 'http://online.worldpay.com'
      self.display_name = 'Worldpay Online Payments'

      def initialize(options={})
        requires!(options, :client_key)
        requires!(options, :service_key)
        @client_key = options[:client_key]
        @service_key = options[:service_key]
        super
      end

      def authorize(money, creditcard, options={})
        # create token
        response = create_token(true, creditcard.first_name+' '+creditcard.last_name, creditcard.month, creditcard.year, creditcard.number, creditcard.verification_value)

        if response.success?
          # Create Authorize Only Order
          options[:authorizeOnly] = true
          post = create_post_for_auth_or_purchase(response.authorization, money, options)

          #puts post
          response = commit(:post, 'orders', post)
        end
        response
      end

      def capture(money, orderCode, options={})
          commit(:post, "orders/#{CGI.escape(orderCode)}/capture", {"captureAmount"=>money}, options)
      end


      def purchase(money, creditcard, options={})
        response = create_token(true, creditcard.first_name+' '+creditcard.last_name, creditcard.month, creditcard.year, creditcard.number, creditcard.verification_value)

        if response.success?
          post = create_post_for_auth_or_purchase(response.authorization, money, options)
          response = commit(:post, 'orders', post, options)
        end
        response
      end

      def refund(money, orderCode, options={})
        obj = money ? {"refundAmount" => money} : {}
        commit(:post, "orders/#{CGI.escape(orderCode)}/refund", obj, options)
      end

     def void(orderCode, options={})
        response = commit(:delete, "orders/#{CGI.escape(orderCode)}", nil, options)
        if !response.success? && response.error_code != 'ORDER_NOT_FOUND'
          response = refund(nil, orderCode)
        end
        response
     end

      def verify(creditcard, options={})
        authorize(0, creditcard, options)
      end

      private


      def create_token(reusable, name, exp_month, exp_year, number, cvc)
        obj = {
          "reusable"=> reusable,
          "paymentMethod"=> {
            "type"=> "Card",
            "name"=> name,
            "expiryMonth"=> exp_month,
            "expiryYear"=> exp_year,
            "cardNumber"=> number,
            "cvc"=> cvc
          },
          "clientKey"=> @client_key
        }

        token_response = commit(:post, 'tokens', obj, {'Authorization' => @service_key})

        token_response
      end


      def create_post_for_auth_or_purchase(token, money, options)
        post = {}

        add_amount(post, money, options, true)

        post = {
          "token" => token,
          "orderDescription" => options[:description],
          "amount" => money,
          "currencyCode" => options[:currency] || default_currency,
          "name" => options[:address]&&options[:address][:name] ? options[:address][:name] : '',
=begin
          "customerIdentifiers" => {
              "product-category"=>"fruits",
              "product-quantity"=>"3",
              "product-quantity"=>"5",
              "product-name"=>"orange"
          },
=end
          "billingAddress" => {
              "address1"=>options[:address]&&options[:address][:address1] ? options[:address][:address1] : '',
              "address2"=>options[:address]&&options[:address][:address2] ? options[:address][:address2] : '',
              "address3"=>"",
              "postalCode"=>options[:address]&&options[:address][:zip] ? options[:address][:zip] : '',
              "city"=>options[:address]&&options[:address][:city] ? options[:address][:city] : '',
              "state"=>options[:address]&&options[:address][:state] ? options[:address][:state] : '',
              "countryCode"=>options[:address]&&options[:address][:country] ? options[:address][:country] : ''
          },
          "customerOrderCode" => options[:order_id],
          "orderType" => "ECOM",
          "authorizeOnly" => options[:authorizeOnly] ? true : false
        }


        post
      end


      def add_amount(post, money, options, include_currency = false)
        currency = options[:currency] || currency(money)
        post[:amount] = localized_amount(money, currency)
        post[:currency] = currency.downcase if include_currency
      end

      def add_address(post, options)
        return unless post[:card] && post[:card].kind_of?(Hash)
        if address = options[:billing_address] || options[:address]
          post[:card][:address_line1] = address[:address1] if address[:address1]
          post[:card][:address_line2] = address[:address2] if address[:address2]
          post[:card][:address_country] = address[:country] if address[:country]
          post[:card][:address_zip] = address[:zip] if address[:zip]
          post[:card][:address_state] = address[:state] if address[:state]
          post[:card][:address_city] = address[:city] if address[:city]
        end
      end

      def add_creditcard(post, creditcard, options)
        card = {}
        if creditcard.respond_to?(:number)
          if creditcard.respond_to?(:track_data) && creditcard.track_data.present?
            card[:swipe_data] = creditcard.track_data
          else
            card[:number] = creditcard.number
            card[:exp_month] = creditcard.month
            card[:exp_year] = creditcard.year
            card[:cvc] = creditcard.verification_value if creditcard.verification_value?
            card[:name] = creditcard.name if creditcard.name
          end

          post[:card] = card
          add_address(post, options)
        elsif creditcard.kind_of?(String)
          if options[:track_data]
            card[:swipe_data] = options[:track_data]
          else
            card = creditcard
          end
          post[:card] = card
        end
      end

      def add_invoice(post, money, options)
        post[:amount] = amount(money)
        post[:currency] = (options[:currency] || currency(money))
      end

      def parse(body)
        if (!body)
          body = {}
        else
          body = JSON.parse(body)
        end
        body
      end

      def headers(options = {})
        headers = {
            "Authorization" => @service_key,
            "Content-Type" => 'application/json',
            "User-Agent" => "Worldpay/v1 ActiveMerchantBindings/#{ActiveMerchant::VERSION}",
            "X-Worldpay-Client-User-Agent" => user_agent,
            "X-Worldpay-Client-User-Metadata" => {:ip => options[:ip]}.to_json
        }
        if options['Authorization']
          headers['Authorization'] = options['Authorization']
        end
        headers
      end

      def commit(method, url, parameters=nil, options = {})

        raw_response = response = nil
        success = false
        begin

          if parameters == nil
            json = nil
          else
            json = parameters.to_json
          end

          raw_response = ssl_request(method, self.live_url + url, json, headers(options))

          if (raw_response != '')
            response = parse(raw_response)
            success = !response.key?("httpStatusCode")
          else
            success = true
            response = {}
          end

        rescue ResponseError => e
          raw_response = e.response.body
          response = response_error(raw_response)
        rescue JSON::ParserError => e
          response = json_error(raw_response)
        end

        if response["orderCode"]
          authorization = response["orderCode"]
        elsif response["token"]
          authorization = response["token"]
        else
          authorization = response["message"]
        end

        Response.new(success,
                     success ? "SUCCESS" : response["message"],
                     response,
                     :test => @service_key[0]=="T" ? true : false,
                     :authorization => authorization,
                     :avs_result => {},
                     :cvv_result => {},
                     :error_code => success ? nil : response["customCode"]
        )
      end

      def response_error(raw_response)
        begin
          parse(raw_response)
        rescue JSON::ParserError
          json_error(raw_response)
        end
      end
      def json_error(raw_response)
        msg = 'Invalid response received from the Worldpay Online Payments API.  Please contact techsupport.online@worldpay.com if you continue to receive this message.'
        msg += "  (The raw response returned by the API was #{raw_response.inspect})"
        {
            "error" => {
                "message" => msg
            }
        }
      end

      def handle_response(response)
        response.body
      end

      def post_data(params)
        return nil unless params

        params.map do |key, value|
          next if value.blank?
          if value.is_a?(Hash)
            h = {}
            value.each do |k, v|
              h["#{key}[#{k}]"] = v unless v.blank?
            end
            post_data(h)
          elsif value.is_a?(Array)
            value.map { |v| "#{key}[]=#{CGI.escape(v.to_s)}" }.join("&")
          else
            "#{key}=#{CGI.escape(value.to_s)}"
          end
        end.compact.join("&")
      end
    end
  end
end
