# aws4-url-gen-dot-net
.NET code for generating pre-signed URLs for Amazon Web Services Signature Version 4.

Based on AWS Documentation: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html

You may need to change the payload hash based on specific service, not entirely sure.  The documentation says to use "UNSIGNED-PAYLOAD" but I had to use the Hex Digest of the SHA256 of an empty string for the service I was dealing with.
