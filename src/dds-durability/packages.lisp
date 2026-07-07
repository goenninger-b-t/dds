(defpackage #:net.goenninger.dds.durability
  (:nicknames #:dds.durability)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation "DDS.DURABILITY — embedded TRANSIENT durability service (ADR 0021 slice 2).")
  (:export #:durable-store #:make-memory-store #:store-put #:store-get-range #:store-topics
           #:store-purge #:store-open #:store-close #:store-count
           #:durable-record #:durable-record-topic #:durable-record-writer-guid #:durable-record-sn
           #:durable-record-key-hash #:durable-record-kind #:durable-record-payload
           #:service-spec #:make-service-spec #:service-spec-matches-p
           #:service-spec-domain #:service-spec-topics #:service-spec-store
           #:service-spec-mode #:service-spec-qos-overrides #:service-spec-name
           #:service-spec-history-kind #:service-spec-history-depth
           #:service-spec-auto-discover #:service-spec-auto-discover-filter
           #:durability-service #:make-durability-service #:service-start #:service-stop #:service-alive-p #:service-add-topic
           #:service-serves-topic-p
           #:durability-service-store #:durability-service-node #:durability-service-nodes
           #:durability-service-topic-names #:durability-service-spec #:durability-service-discovery-node
           #:*durability-error-hook* #:*durability-debug-start-fault*
           #:*durability-auto-discover-interval*
           #:*max-collect-origins*
           #:service-runner #:make-service-runner #:runner-start #:runner-stop #:runner-status
           #:service-runner-services
           #:supervisor #:make-supervisor #:supervisor-start #:supervisor-stop #:supervisor-shed-p
           #:%restart-allowed-p
           #:durability-service-main
           #:parse-durability-config
           #:durability-config-error
           #:%spec->argv
           #:make-encrypted-store #:*dare-error-hook*
           #:make-file-store #:file-store-sync
           #:*compaction-superseded-threshold*
           #:durable-store-sync #:store-sync #:store-delete
           #:make-persistent-store-factory
           #:make-sqlite-store #:make-sqlite-store-factory))
