#! Signature detects a recently created x509 certificate
#! The script alerts when it a x509 certificate has valid lifespan on less than 90 days

@load base/frameworks/notice

module X509;

redef enum Notice::Type += {
ShortLifespanCertificate,
};

event x509_certificate (f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
   {
	local interval_lifespan = cert$not_valid_after - cert$not_valid_before;

    if (interval_lifespan < 90 days)
        {
            for (cid in f$conns)
                NOTICE([$note=ShortLifespanCertificate,
                        $msg="Certificate is valid for less than 90 days",
                        $identifier=cat(f$conns[cid]$id$orig_h,f$conns[cid]$id$resp_h)
                      ]);
        }
   }
