#! Signature detects a recently created x509 certificate
#! The script alerts when it a x509 certificate has been created in the last 7 days (rounded down) 

@load base/frameworks/notice

module X509;

redef enum Notice::Type += {
NewlyCreatedCertificate,
};

event x509_certificate (f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
   {
	local interval_since_creation = network_time() - cert$not_valid_before;

    if (interval_since_creation < 7 days)
        {
            for (cid in f$conns)
                NOTICE([$note=NewlyCreatedCertificate,
                        $msg="Certificate has been created within the last 7 days",
                        $identifier=cat(f$conns[cid]$id$orig_h,f$conns[cid]$id$resp_h)
                      ]);
        }
   }
