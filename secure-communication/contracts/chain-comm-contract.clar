;; SECURE-COMMUNICATION-PROTOCOL - VERSION 0.5
;; Enhanced implementation with connection management and packet acknowledgment

;; Status codes
(define-constant STATUS-ENTITY-MISSING u401)
(define-constant STATUS-ENTITY-EXISTS u402)
(define-constant STATUS-ACCESS-DENIED u403)
(define-constant STATUS-PACKET-MISSING u404)
(define-constant STATUS-PACKET-OVERSIZED u405)
(define-constant STATUS-CRYPTO-FAILURE u406)
(define-constant STATUS-TASK-FAILED u407)
(define-constant STATUS-CONNECTION-MISSING u408)
(define-constant STATUS-CONNECTION-EXISTS u409)
(define-constant STATUS-SELF-CONNECTION-ERROR u410)

;; System parameters
(define-constant PACKET-SIZE-LIMIT u1024)
(define-constant CRYPTO-KEY-LENGTH u33)
(define-constant CONNECTION-LIMIT u50)
(define-constant DEFAULT-LIFETIME-BLOCKS u720) ;; ~5 days (10 min blocks)

;; SYSTEM STATE
(define-data-var system-supervisor principal tx-sender)
(define-data-var packet-counter uint u0)
(define-data-var entity-counter uint u0)

;; DATA STRUCTURES
(define-map entity-registry principal 
  {
    operational: bool,
    crypto-key: (optional (buff 33)),
    registration-time: uint,
    outbound-count: uint,
    inbound-count: uint,
    last-active: uint
  }
)

(define-map packet-registry uint 
  {
    origin: principal,
    destination: principal,
    secure-payload: (buff 1024),
    creation-timestamp: uint,
    acknowledged: bool,
    acknowledgment-timestamp: (optional uint),
    lifetime-end-block: uint
  }
)

(define-map entity-mailbox principal (list 25 uint))

;; Verified connections between entities
(define-map entity-connections principal (list 50 principal))

;; QUERY FUNCTIONS
(define-read-only (fetch-entity-profile (user principal))
  (default-to 
    {
      operational: false,
      crypto-key: none,
      registration-time: u0,
      outbound-count: u0,
      inbound-count: u0,
      last-active: u0
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

(define-read-only (fetch-entity-connections (user principal))
  (default-to (list) (map-get? entity-connections user))
)

;; Check if a connection exists
(define-read-only (check-connection-status (source principal) (target principal))
  (let (
    (connections (fetch-entity-connections source))
  )
    (is-some (index-of connections target))
  )
)

;; Helper functions for blockchain info
(define-private (query-block-time)
  (default-to u0 (get-block-info? time u0))
)

(define-private (query-block-height)
  (default-to u0 (get-block-info? id u0))
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
        registration-time: current-time,
        outbound-count: u0,
        inbound-count: u0,
        last-active: current-time
      }
    )
    
    ;; Initialize empty mailbox
    (map-set entity-mailbox caller (list))
    
    ;; Update counter
    (var-set entity-counter (+ (var-get entity-counter) u1))
    (ok true)
  )
)

(define-public (rotate-crypto-key (new-key (buff 33)))
  (let (
    (caller tx-sender)
    (profile (fetch-entity-profile caller))
    (current-time (query-block-time))
  )
    ;; Verify entity exists
    (asserts! (get operational profile) 
              (err STATUS-ENTITY-MISSING))
    
    ;; Update key and activity timestamp
    (map-set entity-registry caller
      (merge profile { 
        crypto-key: (some new-key),
        last-active: current-time
      })
    )
    
    (ok true)
  )
)

;; CONNECTION MANAGEMENT
(define-public (establish-connection (target-entity principal))
  (let (
    (caller tx-sender)
    (caller-profile (fetch-entity-profile caller))
    (target-profile (fetch-entity-profile target-entity))
    (current-connections (fetch-entity-connections caller))
  )
    ;; Verify both entities exist
    (asserts! (get operational caller-profile) 
              (err STATUS-ENTITY-MISSING))
    (asserts! (get operational target-profile) 
              (err STATUS-ENTITY-MISSING))
    
    ;; Prevent self-connection
    (asserts! (not (is-eq caller target-entity))
              (err STATUS-SELF-CONNECTION-ERROR))
    
    ;; Check if connection already exists
    (asserts! (not (check-connection-status caller target-entity))
              (err STATUS-CONNECTION-EXISTS))
    
    ;; Check connection limit
    (asserts! (< (len current-connections) CONNECTION-LIMIT)
              (err STATUS-ACCESS-DENIED))
    
    ;; Add connection
    (map-set entity-connections 
             caller 
             (append current-connections target-entity))
    
    (ok true)
  )
)

(define-public (terminate-connection (target-entity principal))
  (let (
    (caller tx-sender)
    (current-connections (fetch-entity-connections caller))
  )
    ;; Check if connection exists
    (asserts! (check-connection-status caller target-entity)
              (err STATUS-CONNECTION-MISSING))
    
    ;; Remove connection
    (map-set entity-connections 
             caller 
             (filter remove-target-connection current-connections))
    
    (ok true)
  )
)

;; Helper function for filtering connections
(define-private (remove-target-connection (entity principal))
  (not (is-eq entity target-entity))
)

;; COMMUNICATION FUNCTIONS
(define-public (transmit-packet (to-entity principal) 
                           (secure-payload (buff 1024))
                           (custom-lifetime uint))
  (let (
    (caller tx-sender)
    (sender-profile (fetch-entity-profile caller))
    (recipient-profile (fetch-entity-profile to-entity))
    (packet-id (var-get packet-counter))
    (current-time (query-block-time))
    (current-block (query-block-height))
    (expiration-block (if (> custom-lifetime u0) 
                      (+ current-block custom-lifetime)
                      (+ current-block DEFAULT-LIFETIME-BLOCKS)))
    (recipient-mailbox (fetch-entity-mailbox to-entity))
  )
    ;; Validate both entities
    (asserts! (get operational sender-profile) 
              (err STATUS-ENTITY-MISSING))
    (asserts! (get operational recipient-profile) 
              (err STATUS-ENTITY-MISSING))
    
    ;; Verify connection exists
    (asserts! (check-connection-status caller to-entity)
              (err STATUS-ACCESS-DENIED))
    
    ;; Check mailbox limit
    (asserts! (< (len recipient-mailbox) u25)
              (err STATUS-ACCESS-DENIED))
    
    ;; Store the packet
    (map-set packet-registry packet-id
      {
        origin: caller,
        destination: to-entity,
        secure-payload: secure-payload,
        creation-timestamp: current-time,
        acknowledged: false,
        acknowledgment-timestamp: none,
        lifetime-end-block: expiration-block
      }
    )
    
    ;; Update recipient's mailbox
    (map-set entity-mailbox 
             to-entity
             (append recipient-mailbox packet-id))
    
    ;; Update packet counters
    (map-set entity-registry caller
      (merge sender-profile { 
        outbound-count: (+ (get outbound-count sender-profile) u1),
        last-active: current-time
      })
    )
    
    (map-set entity-registry to-entity
      (merge recipient-profile { 
        inbound-count: (+ (get inbound-count recipient-profile) u1)
      })
    )
    
    ;; Increment counter
    (var-set packet-counter (+ packet-id u1))
    
    (ok packet-id)
  )
)

(define-public (acknowledge-packet (packet-id uint))
  (let (
    (caller tx-sender)
    (packet-data (unwrap! (fetch-packet-details packet-id) 
                     (err STATUS-PACKET-MISSING)))
    (current-time (query-block-time))
    (current-block (query-block-height))
    (mailbox-items (fetch-entity-mailbox caller))
  )
    ;; Verify caller is recipient
    (asserts! (is-eq (get destination packet-data) caller) 
              (err STATUS-ACCESS-DENIED))
    
    ;; Check expiration
    (asserts! (< current-block (get lifetime-end-block packet-data))
              (err STATUS-ACCESS-DENIED))
    
    ;; Update receipt status
    (map-set packet-registry packet-id
      (merge packet-data { 
        acknowledged: true,
        acknowledgment-timestamp: (some current-time)
      })
    )
    
    ;; Remove from mailbox
    (map-set entity-mailbox 
             caller 
             (filter remove-packet-id mailbox-items))
    
    ;; Update activity timestamp
    (map-set entity-registry caller
      (merge (fetch-entity-profile caller) { 
        last-active: current-time
      })
    )
    
    (ok true)
  )
)

(define-public (purge-packet (packet-id uint))
  (let (
    (caller tx-sender)
    (packet-data (unwrap! (fetch-packet-details packet-id) 
                     (err STATUS-PACKET-MISSING)))
    (current-time (query-block-time))
  )
    ;; Verify caller is sender or recipient
    (asserts! (or 
               (is-eq (get origin packet-data) caller)
               (is-eq (get destination packet-data) caller))
             (err STATUS-ACCESS-DENIED))
    
    ;; If recipient is deleting, update mailbox if needed
    (if (and 
         (is-eq (get destination packet-data) caller)
         (not (get acknowledged packet-data)))
        (map-set entity-mailbox 
                 caller 
                 (filter remove-packet-id 
                         (fetch-entity-mailbox caller)))
        true)
    
    ;; Delete the packet
    (map-delete packet-registry packet-id)
    
    ;; Update activity timestamp
    (map-set entity-registry caller
      (merge (fetch-entity-profile caller) { 
        last-active: current-time
      })
    )
    
    (ok true)
  )
)

;; Helper function for filtering items
(define-private (remove-packet-id (id uint))
  (not (is-eq id packet-id))
)

;; MAINTENANCE FUNCTIONS
(define-public (optimize-mailbox)
  (let (
    (caller tx-sender)
    (mailbox-items (fetch-entity-mailbox caller))
    (current-block (query-block-height))
    (valid-mailbox-items (filter is-packet-valid mailbox-items))
  )
    ;; Update mailbox with only valid packets
    (map-set entity-mailbox caller valid-mailbox-items)
    
    ;; Update activity timestamp
    (map-set entity-registry caller
      (merge (fetch-entity-profile caller) { 
        last-active: (query-block-time)
      })
    )
    
    (ok true)
  )
)

;; Helper function to check if a packet is valid (not expired)
(define-private (is-packet-valid (packet-id uint))
  (let (
    (packet-data (unwrap! (fetch-packet-details packet-id) false))
    (current-block (query-block-height))
  )
    (if (and
         packet-data
         (< current-block (get lifetime-end-block packet-data)))
        true
        false)
  )
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

(define-public (transfer-supervision (new-supervisor principal))
  (begin
    ;; Only current supervisor can transfer
    (asserts! (is-eq tx-sender (var-get system-supervisor)) 
              (err STATUS-ACCESS-DENIED))
    (var-set system-supervisor new-supervisor)
    (ok true)
  )
)