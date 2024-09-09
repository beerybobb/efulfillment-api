const https = require("https");
const crypto = require("crypto");

// Function to verify Shopify Webhook
function verifyShopifyWebhook(event) {
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;

  // Log the entire incoming event headers for debugging
  console.log("Incoming Headers:", JSON.stringify(event.headers, null, 2));

  if (!event.body) {
    console.error("Missing body in the event");
    return false;
  }

  // Convert all headers to lowercase for case-insensitive matching
  const headers = {};
  for (let key in event.headers) {
    headers[key.toLowerCase()] = event.headers[key];
  }

  const hmacHeader = headers["x-shopify-hmac-sha256"]; // Always use the lowercase key
  if (!hmacHeader) {
    console.error("Missing HMAC header in the event");
    return false;
  }

  // Log the received HMAC for debugging
  console.log("Received HMAC Header:", hmacHeader);

  // Calculate the HMAC
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(event.body, "utf8");
  const calculatedHmac = hmac.digest("base64");

  // Log the calculated HMAC for comparison
  console.log("Calculated HMAC:", calculatedHmac);

  // Compare the received and calculated HMAC
  return crypto.timingSafeEqual(Buffer.from(hmacHeader), Buffer.from(calculatedHmac));
}

exports.sendOrder = async (event) => {
  // Verify the webhook signature
  if (!verifyShopifyWebhook(event)) {
    console.error("Unauthorized - Invalid Shopify Webhook Signature");
    return {
      statusCode: 401,
      body: "Unauthorized - Invalid Shopify Webhook Signature",
    };
  }

  // Log the Shopify order data after verification
  console.log("Verified Shopify Order Data:", event.body);

  // Shopify order data passed from the webhook event
  const order = JSON.parse(event.body);

  // Filter out line items with "fulfillment_service": "printful"
  order.line_items = order.line_items.filter(
    (item) => item.fulfillment_service !== "printful"
  );

  // If no items are left after filtering, log and exit
  if (order.line_items.length === 0) {
    console.log("No efulfillment items");
    return {
      statusCode: 200,
      body: "No efulfillment items",
    };
  }

  // Generate XML data from Shopify order
  const xmlOrder = generateXML(order);

  // Define options for HTTPS request to eFulfillment Service
  const options = {
    hostname: "fcp.efulfillmentservice.com",
    port: 443,
    path: "/xml/orders/",
    method: "POST",
    headers: {
      "Content-Type": "text/xml",
    },
  };

  // Return a Promise to handle asynchronous HTTPS request
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";

      // Collect response data
      res.on("data", (chunk) => {
        data += chunk;
      });

      // On request end, resolve or reject based on response
      res.on("end", () => {
        console.log(`eFulfillment Response Status Code: ${res.statusCode}`);  // Log response status code
        console.log(`eFulfillment Response Body: ${data}`);  // Log response body
        
        if (res.statusCode === 200) {
          console.log(`Order submission successful for Order ID: ${order.id}`);  // Log success
          resolve({ statusCode: 200, body: data });
        } else {
          console.error(`Order submission failed for Order ID: ${order.id}, Status Code: ${res.statusCode}`);  // Log failure
          reject({ statusCode: res.statusCode, body: data });
        }
      });
    });

    req.on("error", (error) => {
      console.error(`Error submitting order for Order ID: ${order.id}, Error: ${error.message}`);  // Log error
      reject(error);
    });

    // Send the XML order data
    req.write(xmlOrder);
    req.end();
  });
};

// Function to convert Shopify order into the required XML structure
function generateXML(order) {
  // Determine the shipping method based on the destination country
  const shippingMethod =
    order.shipping_address.country_code === "US"
      ? "USPS_MEDIA"
      : "EPGEPACKT";

  // Check if it's a test order
  const version = order.test ? "TEST" : "0.6"; // Set to 'TEST' if test_mode is true, else '0.6'

  return `
      <OrderSubmitRequest>
          <Version>${version}</Version>
          <MerchantId>${process.env.MERCHANT_ID}</MerchantId>
          <MerchantName>${process.env.MERCHANT_NAME}</MerchantName>
          <MerchantToken>${process.env.MERCHANT_TOKEN}</MerchantToken>
          <OrderList>
              <Order>
                  <OrderNumber>${order.id}</OrderNumber>
                  <ShippingMethod>${shippingMethod}</ShippingMethod>
                  <ShippingAddress>
                      <FirstName>${order.shipping_address.first_name}</FirstName>
                      <LastName>${order.shipping_address.last_name}</LastName>
                      <Address1>${order.shipping_address.address1}</Address1>
                      <City>${order.shipping_address.city}</City>
                      <State>${order.shipping_address.province}</State>
                      <PostalCode>${order.shipping_address.zip}</PostalCode>
                      <Country>${order.shipping_address.country_code}</Country>
                  </ShippingAddress>
                  <ItemList>
                      ${order.line_items
                        .map(
                          (item) => `
                          <Item>
                              <Sku>${item.sku}</Sku>
                              <Quantity>${item.quantity}</Quantity>
                          </Item>`
                        )
                        .join("")}
                  </ItemList>
              </Order>
          </OrderList>
      </OrderSubmitRequest>
  `;
}
