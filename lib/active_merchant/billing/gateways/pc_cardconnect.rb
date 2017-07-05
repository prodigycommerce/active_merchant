module ActiveMerchant
  module Billing
    class PcCardconnectGateway < Gateway

      self.test_url = 'https://fts.cardconnect.com:6443/cardconnect/rest'
      self.live_url = ''

      self.default_currency = 'USD'
      self.money_format = :cents
      self.supported_countries = ['US']

      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :jcb, :diners_club]

      self.homepage_url = 'http://www.cardconnect.com/'
      self.display_name = 'CardConnect'

      def initialize(options = {})
        requires!(options, :username, :password, :merchid)
        super
      end

      def purchase(amount, payment_method, options = {})
        params = {endpoint: 'auth', capture: 'Y'}

        add_invoice(params, options)
        add_payment_method(params, payment_method)
        add_address(params, options)
        add_level2(params, options)
        add_level3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def authorize(amount, payment_method, options = {})
        params = {endpoint: 'auth'}

        add_invoice(params, options)
        add_payment_method(params, payment_method)
        add_address(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def capture(amount, authorization, options = {})
        params = {endpoint: 'capture'}

        add_authorization_info(params, authorization)
        add_level2(params, options)
        add_level3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def refund(amount, authorization, options = {})
        params = {endpoint: 'refund'}

        add_authorization_info(params, authorization)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def void(authorization, options = {})
        params = {endpoint: 'void'}

        add_authorization_info(params, authorization)

        commit(params, options)
      end

      def verify(creditcard, options={})
        params = {endpoint: 'auth', amount: '0', currency: (options[:currency] || default_currency).upcase}

        add_invoice(params, options)
        add_credit_card(params, creditcard)
        add_address(params, options)

        commit(params, options)
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript.
          gsub(%r((Authorization: Basic )\w+), '\1[FILTERED]').
          gsub(%r((\\?"account\\?":\\?")\d+), '\1[FILTERED]').
          gsub(%r((\\?"cvv2\\?":\\?")\d+), '\1[FILTERED]').
          gsub(%r((\\?"merchid\\?":\\?")\d+), '\1[FILTERED]')
      end

      private

      def add_invoice(params, options)
        params[:orderid] = options[:order_id]
      end

      def add_payment_method(params, payment_method)
        if payment_method.is_a? Hash
          add_token(params, payment_method)
        else
          add_credit_card(params, payment_method)
        end
      end

      def add_token(params, token)
        params[:accttype] = token[:type]
        params[:name] = token[:cardholder_name]
        params[:account] = token[:token]
        params[:expiry] = token[:exp_date]
      end

      def add_credit_card(params, creditcard)
        params[:accttype] = creditcard.brand
        params[:name] = creditcard.name
        params[:account] = creditcard.number
        params[:expiry] = "#{format(creditcard.month, :two_digits)}#{format(creditcard.year, :two_digits)}"
        params[:cvv2] = creditcard.verification_value if creditcard.verification_value?
        params[:tokenize] = 'Y'
      end

      def add_address(params, options)
        address = options[:billing_address]
        return unless address

        params[:address] = address[:address1] if address[:address1]
        params[:city] = address[:city] if address[:city]
        params[:region] = address[:state] if address[:state]
        params[:postal] = address[:zip] if address[:zip]
        params[:country] = address[:country] if address[:country]
      end

      def add_level2(params, options)
        level2 = options[:level2]
        return unless level2

        params[:ponumber] = options[:order_id]
        params[:taxamnt] = level2[:tax_amount]
      end

      def add_level3(params, options)
        level3 = options[:level3]
        return unless level3

        params[:frtamnt] = level3[:shipping_amount]
        params[:dutyamnt] =  level3[:duty_amount]
        params[:shiptozip] = level3[:ship_to_zip]
        params[:shipfromzip] = level3[:ship_from_zip]
        params[:shiptocountry] = level3[:ship_to_country]
        params[:items] = []
        level3[:line_items].each_with_index do |item, index|
          params[:items] <<
          {
            :lineno => index + 1,
            :material => item[:commodity_code],
            :description => item[:description],
            :upc => item[:product_code],
            :quantity => item[:quantity],
            :uom => item[:unit_of_measure],
            :unitcost => item[:price]
          }
        end
        params
      end

      def add_amount(params, money, options)
        params[:currency] = (options[:currency] || default_currency).upcase
        params[:amount] = amount(money)
      end

      def add_authorization_info(params, authorization)
        retref, authcode, amount = authorization.split('|')
        params[:retref] = retref
        params[:authcode] = authcode
      end

      def commit(params, options)
        params[:merchid] = @options[:merchid]
        if test?
          url = "#{test_url}/#{params[:endpoint]}"
        else
          url = "#{live_url}/#{params[:endpoint]}"
        end

        begin
          body = params.to_json
          response = parse(ssl_request(:put, url, body, headers))
        rescue ResponseError => e
          response = response_error(e.response.body)
        rescue JSON::ParserError
          response = json_error(raw_response)
        end

        Response.new(
          success_from(response),
          response['resptext'],
          response,
          test: test?,
          authorization: success_from(response) ? authorization_from(params, response) : '',
          avs_result: {code: response['avsresp']},
          cvv_result: response['cvvresp'],
          error_code: error_code(response, success_from(response)),
          token: response['token']
        )
      end

      def success_from(response)
        response['respstat'] == 'A'
      end

      def authorization_from(params, response)
        [
          response['retref'],
          response['authcode'],
          response['amount']
        ].join('|')
      end

      def error_code(response, success)
        return if success
        [
          response['respcode'],
          response['resptext']
        ].join('|')
      end

      def headers
        auth = Base64.strict_encode64("#{@options[:username]}:#{@options[:password]}").strip
        {
          'Content-Type' => 'application/json',
          'Authorization'  => 'Basic ' + auth,
        }
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