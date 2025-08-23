;; Signature Verification Contract
;; A utility contract for message signature verification on Stacks blockchain
;; Provides secure signature verification and message validation functionality

;; Define constants for error handling
(define-constant err-invalid-signature (err u200))
(define-constant err-invalid-message (err u201))
(define-constant err-signature-verification-failed (err u202))
(define-constant err-invalid-public-key (err u203))

;; Data variables
(define-data-var contract-name (string-ascii 64) "Signature Verification Utilities")
(define-data-var contract-version (string-ascii 16) "1.0.0")

;; Map to store verified signatures for audit purposes
(define-map verified-signatures 
  {message-hash: (buff 32), public-key: (buff 33)}
  {verified-at: uint, verified-by: principal})

;; Function 1: Verify Message Signature
;; Verifies a message signature against a public key using secp256k1 cryptography
(define-public (verify-message-signature 
  (message (buff 1024)) 
  (signature (buff 65)) 
  (public-key (buff 33)))
  (let (
    (message-hash (sha256 message))
    (verification-result (secp256k1-verify message-hash signature public-key))
  )
    (begin
      ;; Validate inputs
      (asserts! (> (len message) u0) err-invalid-message)
      (asserts! (is-eq (len signature) u65) err-invalid-signature)
      (asserts! (is-eq (len public-key) u33) err-invalid-public-key)
      
      ;; Perform signature verification
      (asserts! verification-result err-signature-verification-failed)
      
      ;; Store verification record for audit trail
      (map-set verified-signatures
        {message-hash: message-hash, public-key: public-key}
        {verified-at: stacks-block-height, verified-by: tx-sender})
      
      ;; Return success with verification details
      (ok {
        verified: true,
        message-hash: message-hash,
        verifier: tx-sender,
        block-height: stacks-block-height
      }))))

;; Function 2: Batch Verify Multiple Signatures
;; Verifies multiple message-signature pairs efficiently in a single transaction
(define-public (batch-verify-signatures 
  (messages (list 10 (buff 1024)))
  (signatures (list 10 (buff 65))) 
  (public-keys (list 10 (buff 33))))
  (let (
    (messages-len (len messages))
    (signatures-len (len signatures))
    (public-keys-len (len public-keys))
  )
    (begin
      ;; Ensure all lists have the same length
      (asserts! (and 
        (is-eq messages-len signatures-len)
        (is-eq signatures-len public-keys-len)) err-invalid-signature)
      
      ;; Verify each signature in the batch
      (ok (map verify-single-in-batch 
        messages 
        signatures 
        public-keys)))))

;; Helper function for batch verification
(define-private (verify-single-in-batch 
  (message (buff 1024)) 
  (signature (buff 65)) 
  (public-key (buff 33)))
  (let (
    (message-hash (sha256 message))
    (is-valid (and
      (> (len message) u0)
      (is-eq (len signature) u65)
      (is-eq (len public-key) u33)
      (secp256k1-verify message-hash signature public-key)))
  )
    {
      message-hash: message-hash,
      is-verified: is-valid,
      public-key: public-key
    }))

;; Read-only function to get verification history
(define-read-only (get-verification-record 
  (message-hash (buff 32)) 
  (public-key (buff 33)))
  (map-get? verified-signatures {message-hash: message-hash, public-key: public-key}))

;; Read-only function to get contract information
(define-read-only (get-contract-info)
  (ok {
    name: (var-get contract-name),
    version: (var-get contract-version),
    current-block: stacks-block-height
  }))

;; Read-only function to validate message format
(define-read-only (validate-message-format (message (buff 1024)))
  (ok {
    is-valid: (> (len message) u0),
    message-length: (len message),
    message-hash: (sha256 message)
  }))