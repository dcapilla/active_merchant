module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class NetworkTokenizationCreditCard < CreditCard
      # A +NetworkTokenizationCreditCard+ object represents a tokenized credit card 
      # using the EMV Network Tokenization specification, http://www.emvco.com/specifications.aspx?id=263.
      #
      # It includes all fields of the +CreditCard+ class with additional fields for 
      # verification data that must be given to gateways through existing fields (3DS / EMV).
      #
      # The only tested usage of this at the moment is with an Apple Pay decrupted PKPaymentToken, 
      # https://developer.apple.com/library/prerelease/ios/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

      attr_accessor :payment_cryptogram, :eci, :transaction_id
    end
  end
end
