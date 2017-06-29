module ActiveMerchant
  module Billing
    class PcNmiGateway < Gateway

      self.test_url = 'https://secure.networkmerchants.com/api/transact.php'
      self.live_url = 'https://secure.networkmerchants.com/api/transact.php'

      self.default_currency = 'USD'
      self.money_format = :cents
      self.supported_countries = ['US']

      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :jcb, :diners_club]

      self.homepage_url = 'http://www.nmi.com/'
      self.display_name = 'Network Merchants Inc (NMI)'

      def initialize(options = {})
        requires!(options, :username, :password)
        super
      end

      def purchase(amount, payment_method, options = {})
        params = {type: 'sale'}

        add_invoice(params, options)
        add_payment_method(params, payment_method)
        add_address(params, options)
        add_level2(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def authorize(amount, payment_method, options = {})
        params = {type: 'auth'}

        add_invoice(params, options)
        add_payment_method(params, payment_method)
        add_address(params, options)
        add_level2(params, options)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def capture(amount, authorization, options = {})
        params = {type: 'capture'}

        add_authorization_info(params, authorization)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def refund(amount, authorization, options = {})
        params = {type: 'refund'}

        add_authorization_info(params, authorization)
        add_amount(params, amount, options)

        commit(params, options)
      end

      def void(authorization, options = {})
        params = {type: 'void'}

        add_authorization_info(params, authorization)

        commit(params, options)
      end

      def verify(creditcard, options = {})
        params = {type: 'validate'}

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
          gsub(%r((\\?"username\\?":\\?")\d+), '\1[FILTERED]').
          gsub(%r((\\?"password\\?":\\?")\d+), '\1[FILTERED]').
          gsub(%r((\\?"ccnumber\\?":\\?")\d+), '\1[FILTERED]').
          gsub(%r((\\?"cvv\\?":\\?")\d+), '\1[FILTERED]')
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
        params[:customer_vault_id] = token[:token]
        params[:exp_date] = token[:exp_date]
      end

      def add_credit_card(params, creditcard)
        params[:ccnumber] = creditcard.number
        params[:first_name] = creditcard.first_name
        params[:last_name] = creditcard.last_name
        params[:ccexp] = "#{format(creditcard.month, :two_digits)}#{format(creditcard.year, :two_digits)}"
        params[:cvv] = creditcard.verification_value if creditcard.verification_value?
        params[:customer_vault] = 'add_customer'
      end

      def add_address(params, options)
        address = options[:billing_address]
        return unless address

        params[:address1] = address[:address1] if address[:address1]
        params[:city] = address[:city] if address[:city]
        params[:state] = address[:state] if address[:state]
        params[:zip] = address[:zip] if address[:zip]
        params[:country] = address[:country] if address[:country]
      end

      def add_level2(params, options)
        level2 = options[:level2]
        level3 = options[:level3]
        return unless level2

        params[:tax] = level2[:tax_amount]
        params[:ponumber] = options[:order_id]
        params[:shipping] = level3[:shipping_amount]
      end

      def add_amount(params, money, options)
        params[:currency] = (options[:currency] || default_currency).upcase
        params[:amount] = amount(money)
      end

      def add_authorization_info(params, authorization)
        transactionid, authcode, amount = authorization.split('|')
        params[:transactionid] = transactionid
      end

      def commit(params, options)
        params[:username] = @options[:username]
        params[:password] = @options[:password]
        if test?
          url = test_url
        else
          url = live_url
        end

        body = params.to_query
        response = parse(ssl_post(url, body, headers))

        Response.new(
          success_from(response),
          response[:responsetext],
          response,
          test: test?,
          authorization: authorization_from(params, response),
          avs_result: {code: response[:avsresponse]},
          cvv_result: response[:cvvresponse],
          error_code: error_code(response, success_from(response)),
          token: response[:customer_vault_id]
        )
      end

      def success_from(response)
        response[:response] == '1'
      end

      def authorization_from(params, response)
        [
          response[:transactionid],
          response[:authcode],
          params[:amount]
        ].join('|')
      end

      def headers
        { "Content-Type"  => "application/x-www-form-urlencoded;charset=UTF-8" }
      end

      def parse(body)
        Hash[CGI::parse(body).map { |k,v| [k.intern, v.first] }]
      end

      def error_code(response, success)
        return if success
        [
          response[:response],
          response[:responsetext]
        ].join('|')
      end
    end
  end
end