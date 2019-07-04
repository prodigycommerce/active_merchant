module ActiveMerchant
  module Billing
    class PcMxmerchantGateway < Gateway
      self.test_url = 'https://sandbox.api.mxmerchant.com/checkout/v3'
      self.live_url = 'https://api.mxmerchant.com/checkout/v3'

      self.default_currency = 'USD'
      self.money_format = :dollars
      self.supported_countries = ['US']

      self.supported_cardtypes = %i[visa master american_express discover jcb diners_club]

      self.homepage_url = 'http://www.mxmerchant.com'
      self.display_name = 'MX Merchant'

      AVS_CODE_MAPPING = {
        '0' => 'D',
        '1' => 'C',
        '2' => 'B',
        '3' => 'U',
        '4' => 'R',
        'A' => 'A',
        'B' => 'B',
        'C' => 'C',
        'D' => 'D',
        'E' => 'E',
        'F' => 'F',
        'G' => 'G',
        'I' => 'I',
        'M' => 'M',
        'N' => 'N',
        'P' => 'P',
        'R' => 'R',
        'S' => 'S',
        'U' => 'U',
        'W' => 'W',
        'X' => 'X',
        'Y' => 'Y',
        'Z' => 'Z'
      }.freeze

      CVV_CODE_MAPPING = {
        '0' => 'M',
        '1' => 'N',
        '2' => 'S',
        '3' => 'S',
        '4' => 'U',
        'M' => 'M',
        'N' => 'N',
        'P' => 'P',
        'S' => 'S',
        'U' => 'U',
        'X' => 'X'
      }.freeze

      def initialize(options = {})
        requires!(options, :username, :password, :merchid)
        super
      end

      def purchase(amount, payment_method, options = {})
        params = {}

        add_invoice(params, options)
        add_payment_method(params, payment_method, options)
        add_level2(params, options)
        add_level3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def authorize(amount, payment_method, options = {})
        params = { authOnly: true }

        add_invoice(params, options)
        add_payment_method(params, payment_method, options)
        add_level2(params, options)
        add_level3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def capture(amount, authorization, options = {})
        params = { authOnly: false, tenderType: 'Card' }

        add_authorization_authcode(params, authorization)
        add_authorization_token(params, authorization)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def refund(amount, authorization, options = {})
        params = { tenderType: 'Card' }

        add_authorization_token(params, authorization)
        add_refund_amount(params, amount, options)

        commit(params, options)
      end

      def void(authorization, _options = {})
        params = {}

        add_authorization_id(params, authorization)

        commit_delete(params)
      end

      def verify(creditcard, options = {})
        params = {}

        add_invoice(params, options)
        add_credit_card(params, creditcard, options)

        commit_verify(params)
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript.
          gsub(/(Authorization: Basic )\w+/, '\1FILTERED]').
          gsub(/(\\?"number\\?":\\?")\d+/, '\1[FILTERED]').
          gsub(/(\\?"cvv\\?":\\?")\d+/, '\1[FILTERED]').
          gsub(/(\\?"merchid\\?":\\?")\d+/, '\1[FILTERED]')
      end

      private

      def add_invoice(params, options)
        params[:invoice] = options[:order_id][0, 8] if options[:order_id]
      end

      def add_payment_method(params, payment_method, options)
        if payment_method.is_a? Hash
          add_token(params, payment_method, options)
        else
          add_credit_card(params, payment_method, options)
        end
      end

      def add_token(params, token, options)
        card_account = {}
        address = options[:billing_address]

        card_account[:name] = token[:cardholder_name]
        card_account[:token] = token[:token]
        card_account[:expiryMonth] = token[:exp_date][0, 2]
        card_account[:expiryYear] = token[:exp_date][-2..-1]
        card_account[:avsZip] = address[:zip] if address[:zip]
        card_account[:avsStreet] = address[:address1] if address[:address1]
        card_account[:cardPresent] = false

        params[:tenderType] = 'Card'
        params[:cardAccount] = card_account
      end

      def add_credit_card(params, creditcard, options)
        card_account = {}
        address = options[:billing_address]

        card_account[:name] = creditcard.name
        card_account[:number] = creditcard.number
        card_account[:expiryMonth] = format(creditcard.month, :two_digits)
        card_account[:expiryyear] = format(creditcard.year, :two_digits)
        card_account[:cvv] = creditcard.verification_value if creditcard.verification_value?
        card_account[:avsZip] = address[:zip] if address[:zip]
        card_account[:avsStreet] = address[:address1] if address[:address1]
        card_account[:cardPresent] = false

        params[:tenderType] = 'Card'
        params[:cardAccount] = card_account
        params[:tokenize] = 'Y'
      end

      def add_level2(params, options)
        level2 = options[:level2]
        return unless level2

        params[:customerCode] = options[:order_id]
        params[:tax] = level2[:tax_amount]
        params[:taxExempt] = tax_exempt(level2[:tax_amount])
      end

      def add_level3(params, options)
        level3 = options[:level3]
        return unless level3

        params[:departmentName] = 'Purchasing'
        params[:discountAmount] = level3[:discount_amount]
        params[:dutyAmount] = '0.00'
        params[:shipAmount] = level3[:shipping_amount]
        params[:shipToZip] = level3[:ship_to_zip]
        params[:shipToCountry] = level3[:ship_to_country]
        params[:purchases] = []
        level3[:line_items].each do |item|
          params[:purchases] <<
            {
              description: item[:description],
              quantity: item[:quantity],
              code: item[:commodity_code],
              unitPrice: item[:price],
              unitOfMeasure: item[:unit_of_measure],
              extendedAmount: item[:line_total]
            }
        end
      end

      def add_amount(params, money, _options)
        params[:amount] = amount(money)
      end

      def add_refund_amount(params, money, _options)
        refund_amount = amount(money)
        params[:amount] = "-#{refund_amount}"
      end

      def add_authorization_authcode(params, authorization)
        _id, authcode, _token, = authorization.split('|')

        params[:authCode] = authcode
      end

      def add_authorization_token(params, authorization)
        _id, _authcode, token, = authorization.split('|')

        params[:cardAccount] = { token: token }
      end

      def add_authorization_id(params, authorization)
        id, _authcode, _token, = authorization.split('|')

        params[:id] = id
      end

      def tax_exempt(tax_amount)
        tax_amount.to_f == 0
      end

      def commit(params, _options)
        params[:merchantId] = @options[:merchid]

        token = params.delete(:tokenize) ? tokenize_card(params) : nil

        url = "#{base_url}/payment?echo=true"

        begin
          body = params.to_json
          raw_response = ssl_post(url, body, headers)
          response = parse(raw_response)
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
          avs_result: { code: AVS_CODE_MAPPING[response.dig('risk', 'avsResponseCode')] },
          cvv_result: CVV_CODE_MAPPING[response.dig('risk', 'cvvResponseCode')],
          error_code: error_code(response, success_from(response)),
          token: token
        )
      end

      def commit_delete(params)
        url = "#{base_url}/payment/#{params[:id]}"

        begin
          ssl_request(:delete, url, nil, headers)
          success = true
          message = 'Approved'
        rescue ResponseError => _e
          success = false
          message = 'Declined'
        end

        Response.new(
          success,
          message,
          {},
          test: test?
        )
      end

      def commit_verify(params)
        token = tokenize_card(params)

        if token
          success = true
          message = 'Approved'
          token = token
        else
          success = false
          message = 'Declined'
        end

        Response.new(
          success,
          message,
          {},
          test: test?,
          token: token
        )
      end

      def tokenize_card(params)
        url = "#{base_url}/vault?token=#{limited_use_token}"

        card = params[:cardAccount]

        body = card.to_json
        raw_response = ssl_post(url, body, headers)
        parse("[#{raw_response}]")[0]
      rescue ResponseError, JSON::ParserError
        nil
      end

      def limited_use_token
        url = "#{base_url}/auth/token/#{@options[:merchid]}"

        raw_response = ssl_post(url, nil, headers)
        parse("[#{raw_response}]")[0]
      rescue ResponseError, JSON::ParserError
        nil
      end

      def success_from(response)
        response['status'] == 'Approved'
      end

      def authorization_from(_params, response)
        [
          response['id'],
          response['authCode'],
          response['paymentToken']
        ].join('|')
      end

      def error_code(response, success)
        return if success
        response['errorCode']
      end

      def handle_message(response, success)
        if success
          response['status']
        elsif response.key?('details')
          response['details'].first
        elsif response.key?('message')
          response['message']
        elsif response.key?('error')
          response['error']
        else
          response['status']
        end
      end

      def headers
        auth = Base64.strict_encode64("#{@options[:username]}:#{@options[:password]}").strip
        {
          'Content-Type' => 'application/json',
          'Authorization' => 'Basic ' + auth
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
        { 'error' => "Unable to parse response: #{raw_response.inspect}" }
      end

      def base_url
        @base_url ||= test? ? test_url : live_url
      end
    end
  end
end
