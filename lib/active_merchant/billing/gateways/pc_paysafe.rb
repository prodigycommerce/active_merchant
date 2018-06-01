module ActiveMerchant
  module Billing
    class PcPaysafeGateway < Gateway
      self.test_url = 'https://api.test.paysafe.com'
      self.live_url = 'https://api.paysafe.com'

      self.default_currency = 'USD'
      self.money_format = :cents
      self.supported_countries = ['US']

      self.supported_cardtypes = %i[visa master american_express discover jcb diners_club]

      self.homepage_url = 'https://www.paysafe.com/'
      self.display_name = 'Paysafe'

      AVS_CODE_MAPPING = {
        'MATCH' => 'Y',
        'MATCH_ADDRESS_ONLY' => 'B',
        'MATCH_ZIP_ONLY' => 'P',
        'NO_MATCH' => 'N',
        'NOT_PROCESSED' => 'R',
        'UNKNOWN' => 'U'
      }.freeze

      CVV_CODE_MAPPING = {
        'MATCH' => 'M',
        'NO_MATCH' => 'N',
        'NOT_PROCESSED' => 'P',
        'UNKNOWN' => 'U'
      }.freeze

      def initialize(options = {})
        requires!(options, :username, :password, :merchid)
        super
      end

      def purchase(amount, payment_method, options = {})
        params = { endpoint: "/cardpayments/v1/accounts/#{@options[:merchid]}/auths", settleWithAuth: true, dupCheck: false }

        add_invoice(params, options)
        add_payment_method(params, payment_method, options)
        add_level2_3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def authorize(amount, payment_method, options = {})
        params = { endpoint: "/cardpayments/v1/accounts/#{@options[:merchid]}/auths", settleWithAuth: false, dupCheck: false }

        add_invoice(params, options)
        add_payment_method(params, payment_method, options)
        add_level2_3(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def capture(amount, authorization, options = {})
        params = { endpoint: "/cardpayments/v1/accounts/#{@options[:merchid]}/auths/#{authorization}/settlements", dupCheck: false }

        add_invoice(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def refund(amount, authorization, options = {})
      params = { endpoint: "/cardpayments/v1/accounts/#{@options[:merchid]}/settlements/#{authorization}/refunds", dupCheck: false }

        add_invoice(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def void(authorization, options = {})
        params = { endpoint: "/cardpayments/v1/accounts/#{@options[:merchid]}/auths/#{authorization}/voidauths", dupCheck: false }

        add_invoice(params, options)

        commit(params, options)
      end

      def verify(creditcard, options = {})
        params = { endpoint: "/cardpayments/v1/accounts/#{@options[:merchid]}/verifications", dupCheck: false }

        add_invoice(params, options)
        add_credit_card(params, creditcard, options)

        commit(params, options)
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript
          .gsub(/(Authorization: Basic )\w+/, '\1FILTERED]')
          .gsub(/(\\?"cardNum\\?":\\?")\d+/, '\1[FILTERED]')
          .gsub(/(\\?"cvv\\?":\\?")\d+/, '\1[FILTERED]')
          .gsub(/(\\?"merchid\\?":\\?")\d+/, '\1[FILTERED]')
      end

      private

      def add_invoice(params, options)
        params[:merchantRefNum] = options[:order_id]
      end

      def add_payment_method(params, payment_method, options)
        if payment_method.is_a? Hash
          add_token(params, payment_method, options)
        else
          add_credit_card(params, payment_method, options)
        end
      end

      def add_token(params, token, options)
        address = options[:billing_address]

        params[:card] = {
          paymentToken: token[:token]
        }

        params[:billingDetails] = {
          street: address[:address1],
          city: address[:city],
          state: address[:state],
          country: address[:country],
          zip: address[:zip]
        }

        params[:storedCredential] = {
          type: 'ADHOC',
          occurrence: 'SUBSEQUENT'
        }
      end

      def add_credit_card(params, creditcard, options)
        address = options[:billing_address]

        params[:card] = {
          cardNum: creditcard.number,
          cardExpiry: {
            month: format(creditcard.month, :two_digits),
            year: format(creditcard.year, :four_digits)
          },
          cvv: creditcard.verification_value
        }

        params[:billingDetails] = {
          street: address[:address1],
          city: address[:city],
          state: address[:state],
          country: address[:country],
          zip: address[:zip]
        }

        params[:tokenize] = 'Y'
      end

      def add_level2_3(params, options)
        level2 = options[:level2]
        level3 = options[:level3]
        level2level3 = {}
        return unless level2 && level3

        level2level3[:localTaxAmount] = dollars_to_cents(level2[:tax_amount])
        level2level3[:exemptLocalTax] = tax_exempt(level2[:tax_amount])
        level2level3[:nationalTaxAmount] = 0
        level2level3[:freightAmount] = dollars_to_cents(level3[:shipping_amount])
        level2level3[:dutyAmount] = 0
        level2level3[:destinationZip] = level3[:ship_to_zip]
        level2level3[:destinationCountry] = level3[:ship_to_country]
        level2level3[:shipFromZip] = level3[:ship_from_zip]
        level2level3[:lineItems] = []
        level3[:line_items].each do |item|
          level2level3[:lineItems] <<
            {
              description: item[:description],
              productCode: item[:commodity_code],
              quantity: item[:quantity],
              unitAmount: dollars_to_cents(item[:price]),
              taxRate: 0,
              taxAmount: 0,
              totalAmount: dollars_to_cents(item[:line_total])
            }
        end

        params[:level2Level3] = level2level3
      end

      def add_amount(params, money, _options)
        params[:amount] = amount(money)
      end

      def tax_exempt(tax_amount)
        tax_amount.to_f == 0
      end

      def dollars_to_cents(dollars)
        (100 * dollars.to_r).to_i
      end

      def commit(params, _options)
        token = nil
        token = tokenize_card(params) if params.delete(:tokenize)
        endpoint = params.delete(:endpoint)
        url = if test?
                "#{test_url}#{endpoint}"
              else
                "#{live_url}#{endpoint}"
              end

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
          authorization: response['id'],
          avs_result: { code: AVS_CODE_MAPPING[response['avsResponse']] },
          cvv_result: CVV_CODE_MAPPING[response['cvvVerification']],
          error_code: error_code(response, success_from(response)),
          token: token
        )
      end

      def tokenize_card(params)

        url = if test?
                "#{test_url}/customervault/v1/profiles"
              else
                "#{live_url}/customervault/v1/profiles"
              end

        profile = {}
        profile[:merchantCustomerId] = SecureRandom.uuid
        profile[:locale] = 'en_US'
        profile[:card] = params[:card]

        begin
          body = profile.to_json
          raw_response = ssl_post(url, body, headers)
          response = parse(raw_response)
          if response.key?('cards')
            token = response['cards'][0]['paymentToken']
          else
            token = nil
          end
        rescue ResponseError
          token = nil
        rescue JSON::ParserError
          token = nil
        end
      end

      def success_from(response)
        response['status'] == 'COMPLETED' || response['status'] == 'PENDING'
      end

      def error_code(response, success)
        return if success
        response['error']['code'] if response.key?('error')
      end

      def handle_message(response, success)
        if success
          response['status']
        elsif response.key?('error')
          error = response['error']
          if error.key?('fieldErrors')
            "#{error['fieldErrors'][0]['field']} #{error['fieldErrors'][0]['error']}"
          else
            error['message']
          end
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
    end
  end
end