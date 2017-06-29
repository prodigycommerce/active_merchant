module ActiveMerchant
  module Billing
    class PcPayeezyGateway < Gateway

      self.test_url = 'https://api-cert.payeezy.com/v1/transactions'
      self.live_url = 'https://api.payeezy.com/v1/transactions'

      self.default_currency = 'USD'
      self.money_format = :cents
      self.supported_countries = ['US']

      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :jcb, :diners_club]

      self.homepage_url = 'http://www.cardconnect.com/'
      self.display_name = 'Ignite Payments Payeezy'

      CREDIT_CARD_BRAND = {
        'visa' => 'Visa',
        'master' => 'Mastercard',
        'american_express' => 'American Express',
        'discover' => 'Discover',
        'jcb' => 'JCB',
        'diners_club' => 'Diners Club'
      }

      def initialize(options = {})
        requires!(options, :apikey, :apisecret, :token)
        super
      end

      def purchase(amount, payment_method, options = {})
        params = {transaction_type: 'purchase'}

        add_invoice(params, options)
        add_payment_method(params, payment_method)
        add_address(params, options)
        add_level2(params, options)
        add_level3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def authorize(amount, payment_method, options = {})
        params = {transaction_type: 'authorize'}

        add_invoice(params, options)
        add_payment_method(params, payment_method)
        add_address(params, options)
        add_level2(params, options)
        add_level3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def capture(amount, authorization, options = {})
        params = {transaction_type: 'capture'}

        add_authorization_info(params, authorization)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def refund(amount, authorization, options = {})
        params = {transaction_type: 'refund'}

        add_authorization_info(params, authorization)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def void(authorization, options = {})
        params = {transaction_type: 'void'}

        add_authorization_info(params, authorization)
        add_amount(params, amount_from_authorization(authorization), options)

        commit(params, options)
      end

      def verify(creditcard, options = {})
        params = {transaction_type: 'authorize'}

        add_invoice(params, options)
        add_credit_card(params, creditcard)
        add_address(params, options)
        add_amount(params, '0', options)

        commit(params, options)
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript.
          gsub(%r((Token: )(\w|-)+), '\1[FILTERED]').
          gsub(%r((\\?"card_number\\?":\\?")\d+), '\1[FILTERED]').
          gsub(%r((\\?"cvv\\?":\\?")\d+), '\1[FILTERED]')
      end

      private

      def add_invoice(params, options)
        params[:merchant_ref] = options[:order_id]
      end

      def add_payment_method(params, payment_method)
        if payment_method.is_a? Hash
          add_token(params, payment_method)
        else
          add_credit_card(params, payment_method)
        end
      end

      def add_token(params, token)
        token_data = {}

        token_data[:type] = CREDIT_CARD_BRAND[token[:type]]
        token_data[:value] = token[:token]
        token_data[:cardholder_name] = token[:cardholder_name]
        token_data[:exp_date] = token[:exp_date]

        params[:token][:token_type] = 'FDToken'
        params[:token][:token_data] = token_data
      end

      def add_credit_card(params, creditcard)
        credit_card = {}

        credit_card[:type] = CREDIT_CARD_BRAND[creditcard.brand]
        credit_card[:cardholder_name] = creditcard.name
        credit_card[:card_number] = creditcard.number
        credit_card[:exp_date] = "#{format(creditcard.month, :two_digits)}#{format(creditcard.year, :two_digits)}"
        credit_card[:cvv] = creditcard.verification_value if creditcard.verification_value?

        params[:method] = 'credit_card'
        params[:credit_card] = credit_card
      end

      def add_address(params, options)
        address = options[:billing_address]
        return unless address

        billing_address = {}
        billing_address[:street] = address[:address1] if address[:address1]
        billing_address[:city] = address[:city] if address[:city]
        billing_address[:state_province] = address[:state] if address[:state]
        billing_address[:zip_postal_code] = address[:zip] if address[:zip]
        billing_address[:country] = address[:country] if address[:country]

        params[:billing_address] = billing_address
      end

      def add_level2(params, options)
        level2_data = options[:level2]
        return unless level2_data

        level2 = {}
        level2[:tax1_amount] = level2_data[:tax_amount]
        level2[:customer_ref] = options[:order_id]

        params[:level2] = level2
      end

      def add_level3(params, options)
        level3_data = options[:level3]
        return unless level3_data

        level3 = {}
        level3[:discount_amount] = level3_data[:discount_amount]
        level3[:duty_amount] = level3_data[:duty_amount]
        level3[:freight_amount] = level3_data[:shipping_amount]
        level3[:ship_from_zip] = level3_data[:ship_from_zip]
        level3[:line_items] =[]
        level3_data[:line_items].each do |item|
          level3[:line_items] <<
          {
            :description => item[:description],
            :quantity => item[:quantity],
            :commodity_code => item[:commodity_code],
            :product_code => item[:product_code],
            :unit_cost => item[:price],
            :unit_of_measure => item[:unit_of_measure],
            :line_item_total => item[:line_total]
          }
        end

        params[:level3] = level3
      end

      def add_amount(params, money, options)
        params[:currency_code] = (options[:currency] || default_currency).upcase
        params[:amount] = amount(money)
      end

      def amount_from_authorization(authorization)
        authorization.split('|').last.to_i
      end

      def add_authorization_info(params, authorization)
        transaction_id, transaction_tag, method, _ = authorization.split('|')
        params[:transaction_id] = transaction_id
        params[:transaction_tag] = transaction_tag
        params[:method] = method
      end

      def commit(params, options)
        if test?
          url = test_url
        else
          url = live_url
        end

        if transaction_id = params.delete(:transaction_id)
          url = "#{url}/#{transaction_id}"
        end

        begin
          body = params.to_json
          response = parse(ssl_post(url, body, headers(body)))
        rescue ResponseError => e
          response = response_error(e.response.body)
        rescue JSON::ParserError
          response = json_error(raw_response)
        end

        Response.new(
          success_from(response),
          handle_message(response, success_from(response)),
          response,
          test: test?,
          authorization: authorization_from(params, response),
          avs_result: {code: response['avs']},
          cvv_result: response['cvv2'],
          error_code: error_code(response, success_from(response)),
          token: response.dig(:token, :token_data, :value)
        )
      end

      def success_from(response)
        response['transaction_status'] == 'approved'
      end

      def authorization_from(params, response)
        [
          response['transaction_id'],
          response['transaction_tag'],
          params[:method],
          (response['amount'] && response['amount'].to_i)
        ].join('|')
      end

      def generate_hmac(nonce, current_timestamp, payload)
        message = [
          @options[:apikey],
          nonce.to_s,
          current_timestamp.to_s,
          @options[:token],
          payload
        ].join("")
        hash = Base64.strict_encode64(OpenSSL::HMAC.hexdigest('sha256', @options[:apisecret], message))
        hash
      end

      def headers(payload)
        nonce = (SecureRandom.random_number * 10_000_000_000)
        current_timestamp = (Time.now.to_f * 1000).to_i
        {
          'Content-Type' => 'application/json',
          'apikey' => @options[:apikey],
          'token' => @options[:token],
          'nonce' => nonce.to_s,
          'timestamp' => current_timestamp.to_s,
          'Authorization' => generate_hmac(nonce, current_timestamp, payload)
        }
      end

      def error_code(response, success)
        return if success
        response['Error'].to_h['messages'].to_a.map { |e| e['code'] }.join(', ')
      end

      def handle_message(response, success)
        if success
          "#{response['gateway_message']} - #{response['bank_message']}"
        elsif %w(401 403).include?(response['code'])
          response['message']
        elsif response.key?('Error')
          response['Error']['messages'].first['description']
        elsif response.key?('error')
          response['error']
        elsif response.key?('fault')
          response['fault'].to_h['faultstring']
        else
          response['bank_message']
        end
      end

      def parse(body)
        JSON.parse(body)
      end

      def response_error(raw_response)
        parse(raw_response)
      rescue JSON::ParserError
        json_error(raw_response)
      end

      def json_error(raw_response)
        {"error" => "Unable to parse response: #{raw_response.inspect}"}
      end
    end
  end
end
