package authz

default result := false

result if {
	allow
	not deny
}

default allow := false

allow if count(object.get(input, "allow", [])) == 0

allow if {
	some e in object.get(input, "allow", [])
	match(e, input.request)
}

default deny := false

deny if {
	some e in object.get(input, "deny", [])
	match(e, input.request)
}

match(attributes, request) if {
	regexes_match(object.get(attributes, "endpoints", []), request.endpoint)
	regexes_match(object.get(attributes, "actions", []), request.action)
	regexes_match(object.get(attributes, "buckets", []), request.bucket)
	regexes_match(object.get(attributes, "keys", []), request.key)
	cidrs_match(object.get(attributes, "cidrs", []), request.ip)
}

regexes_match(regexes, _) if {
	count(regexes) == 0
}

regexes_match(regexes, item) if {
	some re in regexes
	regex.match(re, item)
}

cidrs_match(cidrs, _) if {
	count(cidrs) == 0
}

cidrs_match(cidrs, item) if {
	some cidr in cidrs
	net.cidr_contains(cidr, item)
}
