;; SECURE-COMMUNICATION-PROTOCOL - VERSION 0.1
;; Initial implementation with basic functionality

;; Status codes
(define-constant STATUS-ENTITY-MISSING u401)
(define-constant STATUS-ENTITY-EXISTS u402)
(define-constant STATUS-ACCESS-DENIED u403)
(define-constant STATUS-PACKET-MISSING u404)
(define-constant STATUS-PACKET-OVERSIZED u405)
(define-constant STATUS-CRYPTO-FAILURE u406)

;; System parameters
(define-constant PACKET-SIZE-LIMIT u1024)
(define-constant CRYPTO-KEY-LENGTH u33)

;; SYSTEM STATE
(define-data-var system-supervisor principal tx-sender)
(define-data-var packet-counter uint u0)
(define-data-var entity-counter uint u0)

;; DATA STRUCTURES
(define-map entity-registry principal 
  {
    operational: bool,
    crypto-key: (optional (buff 33)),
    registration-time: uint
  }
)

(define-map packet-registry uint 
  {
    origin: principal,
    destination: principal,
    secure-payload: (buff 1024),
    creation-timestamp: uint
  }
)

(define-map entity-mailbox principal (list 10 uint))

;; QUERY FUNCTIONS
(define-read-only (fetch-entity-profile (user principal))
  (default-to 
    {
      operational: false,
      crypto-key: none,
      registration-time: u0
    }
    (map-get? entity-registry user)
  )
)

(define-read-only (check-entity-status (user principal))
  (get operational (fetch-entity-profile user))
)

(define-read-only (fetch-packet-details (packet-id uint))
  (map-get? packet-registry packet-id)
)

(define-read-only (get-system-metrics)
  {
    total-packets: (var-get packet-counter),
    registered-entities: (var-get entity-counter)
  }
)

(define-read-only (fetch-entity-mailbox (user principal))
  (default-to (list) (map-get? entity-mailbox user))
)

;; Helper functions for blockchain info
(define-private (query-block-time)
  (default-to u0 (get-block-info? time u0))
)

;; ENTITY MANAGEMENT
(define-public (register-entity (crypto-key (buff 33)))
  (let (
    (caller tx-sender)
    (profile (fetch-entity-profile caller))
    (current-time (query-block-time))
  )
    ;; Check if entity already exists
    (asserts! (not (get operational profile)) 
              (err STATUS-ENTITY-EXISTS))
    
    ;; Create entity record
    (map-set entity-registry caller
      {
        operational: true,
        crypto-key: (some crypto-key),
        registration-time: current-time
      }
    )
    
    ;; Initialize empty mailbox
    (map-set entity-mailbox caller (list))
    
    ;; Update counter
    (var-set entity-counter (+ (var-get entity-counter) u1))
    (ok true)
  )
)

;; COMMUNICATION FUNCTIONS
(define-public (transmit-packet (to-entity principal) 
                           (secure-payload (buff 1024)))
  (let (
    (caller tx-sender)
    (sender-profile (fetch-entity-profile caller))
    (recipient-profile (fetch-entity-profile to-entity))
    (packet-id (var-get packet-counter))
    (current-time (query-block-time))
    (recipient-mailbox (fetch-entity-mailbox to-entity))
  )
    ;; Validate both entities
    (asserts! (get operational sender-profile) 
              (err STATUS-ENTITY-MISSING))
    (asserts! (get operational recipient-profile) 
              (err STATUS-ENTITY-MISSING))
    
    ;; Check mailbox limit 
    (asserts! (< (len recipient-mailbox) u10)
              (err STATUS-ACCESS-DENIED))
    
    ;; Store the packet
    (map-set packet-registry packet-id
      {
        origin: caller,
        destination: to-entity,
        secure-payload: secure-payload,
        creation-timestamp: current-time
      }
    )
    
    ;; Update recipient's mailbox
    (map-set entity-mailbox 
             to-entity
             (append recipient-mailbox packet-id))
    
    ;; Increment counter
    (var-set packet-counter (+ packet-id u1))
    
    (ok packet-id)
  )
)

(define-public (delete-packet (packet-id uint))
  (let (
    (caller tx-sender)
    (packet-data (unwrap! (fetch-packet-details packet-id) 
                     (err STATUS-PACKET-MISSING)))
  )
    ;; Verify caller is sender or recipient
    (asserts! (or 
               (is-eq (get origin packet-data) caller)
               (is-eq (get destination packet-data) caller))
             (err STATUS-ACCESS-DENIED))
    
    ;; If recipient is deleting, update mailbox
    (if (is-eq (get destination packet-data) caller)
        (map-set entity-mailbox 
                 caller 
                 (filter remove-packet-id 
                         (fetch-entity-mailbox caller)))
        true)
    
    ;; Delete the packet
    (map-delete packet-registry packet-id)
    
    (ok true)
  )
)

;; Helper function for filtering items
(define-private (remove-packet-id (id uint))
  (not (is-eq id packet-id))
)

;; ADMINISTRATION FUNCTIONS
(define-public (initialize-system)
  (begin
    ;; Only supervisor can initialize
    (asserts! (is-eq tx-sender (var-get system-supervisor)) 
              (err STATUS-ACCESS-DENIED))
    (ok true)
  )
)