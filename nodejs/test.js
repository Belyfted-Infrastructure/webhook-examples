const {
  createPrivateKey,
  sign,
  constants,
} = require('node:crypto');


function generateDigitalSignature(payload) {
    const config = {
        pass_phrase: '',
        privateKey: ``
    }


  if (!config.privateKey) {
    throw new Error('Private key not configured');
  }

  // This exact string must also be used as the HTTP request body.
  const body = JSON.stringify(payload);

  const passphrase = config?.pass_phrase
    ? String(config.pass_phrase)
    : undefined;

  if (config.privateKey.includes('ENCRYPTED') && !passphrase) {
    throw new Error(
      'ClearBank private key is encrypted but no pass phrase is set.'
    );
  }

  let privateKey;

  try {
    privateKey = createPrivateKey({
      key: config.privateKey,
      format: 'pem',
      ...(passphrase ? { passphrase } : {}),
    });
  } catch (error) {
    if (
      /pkcs12|cipherfinal|bad decrypt|bad password/i.test(error.message)
    ) {
      throw new Error('Private key decryption failed', { cause: error });
    }

    throw new Error(`Invalid private key: ${error.message}`, {
      cause: error,
    });
  }

  try {
    return sign('sha256', Buffer.from(body, 'utf8'), {
      key: privateKey,
      padding: constants.RSA_PKCS1_PADDING,
    }).toString('base64');
  } catch (error) {
    throw new Error(`Failed to sign request: ${error.message}`, {
      cause: error,
    });
  }
}


async function execute(){
    const payload = {
      "external_reference": "EXT-BIZ-2026-0001",
      "business_name": "Techtonic Solutions Ltd",
      "company_number": "99999999",
      "registration_type": "private-limited-company",
      "date_of_incorporation": "2024-06-15",
      "country_of_incorporation": "GB",
      "company_status": "active",
      "business_description": "Software development, IT consulting, and digital payment technology services.",
      "mcc": "7372",
      "sic_code": "62012",
      "business_size": "micro",
      "website": "https://example.com",
      "registered_address": {
        "line1": "10 Example Street",
        "line2": "Suite 4",
        "city": "London",
        "state": "Greater London",
        "postal_code": "SW1A 1AA",
        "country": "GB"
      },
      "contact": {
        "email": "business@example.com",
        "phone": "+447700900123"
      },
      "annual_turnover": {
        "amount": 150000,
        "currency": "GBP"
      },
      "directors": [
        {
          "roles": [
            "director",
            "owner",
            "persons-with-significant-control"
          ],
          "ownership_percentage": 100,
          "first_name": "Alex",
          "last_name": "Morgan",
          "date_of_birth": "1985-04-12",
          "nationality": "GB",
          "email": "alex.morgan@example.com",
          "phone": "+447700900124",
          "address": {
            "line1": "25 Sample Road",
            "line2": "Apartment 2",
            "city": "London",
            "state": "Greater London",
            "postal_code": "EC1A 1BB",
            "country": "GB"
          },
          "is_us_citizen": false,
          "tax_residencies": [
            {
              "country": "GB",
              "tax_identification_number": "123456789"
            }
          ],
          "identity_document": {
            "file_id": "a2fa75f5-7e34-4d91-b123-ed03c5dd1130",
            "document_type": "passport"
          }
        }
      ],
      "company_documents": [
        {
          "file_id": "a2fa75f5-7e34-4d91-b123-ed03c5dd1130",
          "document_type": "certificate_of_incorporation",
          "expires_at": null
        },
        {
          "file_id": "a2fa75f5-7e34-4d91-b123-ed03c5dd1130",
          "document_type": "proof_of_business_address"
        }
      ],
      "purpose_of_account": [
        "business_operations",
        "receive_customer_payments",
        "pay_suppliers"
      ],
      "source_of_funds": [
        "business_revenue",
        "shareholder_capital"
      ],
      "expected_origin_countries": [
        "GB",
        "NG"
      ],
      "attestations": {
        "information_accurate": true,
        "onboarding_checks_authorised": true
      },
      "metadata": {
        "environment": "sandbox",
        "test_case": "business_onboarding",
        "integration_reference": "TEST-KYB-001"
      }
    };

    // Serialize only once.
    // const body = JSON.stringify(payload);
    const digitalSignature = generateDigitalSignature(payload);

    console.log(digitalSignature)
}

execute();