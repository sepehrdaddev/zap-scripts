/*
 * MIT License
 *
 * Copyright (c) 2022 Sepehrdad
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
var TITLE = "[" + this["zap.script.name"] + "] " + "secrets were found"
var RISK = 2 // 0: info, 1: low, 2: medium, 3: high
var CONFIDENCE = 3 // 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
var SOLUTION = "Rotate the Credentials and remove exposure."

function log(msg) {
	print("[" + this["zap.script.name"] + "] " + msg);
}

function alert(ps, msg, description, evidence) {
	ps.newAlert()
		.setRisk(RISK)
		.setConfidence(CONFIDENCE)
		.setName(TITLE)
		.setDescription(description)
		.setEvidence(evidence)
		.setSolution(SOLUTION)
		.setMessage(msg)
		.raise();
}

function scan(ps, msg, src) {

	var uri = msg.getRequestHeader().getURI();

	var content_type = msg.getResponseHeader().getHeader("Content-Type");

	var ignore_list = [
		"image/png", "image/jpeg", "image/gif",
		"application/x-shockwave-flash", "application/pdf"
	];

	if (ignore_list.indexOf(content_type) >= 0) {
		log("ignoring scan for " + uri);
		return;
	}

	log("scanning " + uri);

	var rules = {
		"GitLab Personal Access Token": "glpat-[0-9a-zA-Z-\_]{20}",
		"AWS key": "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
		"PKCS8 private key": "-----BEGIN PRIVATE KEY-----",
		"RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
		"SSH private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
		"PGP private key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"GitHub Personal Access Token": "ghp_[0-9a-zA-Z]{36}",
		"GitHub OAuth Access Token": "gho_[0-9a-zA-Z]{36}",
		"SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
		"SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
		"GitHub App Token": "(ghu|ghs)_[0-9a-zA-Z]{36}",
		"GitHub Refresh Token": "ghr_[0-9a-zA-Z]{76}",
		"Shopify shared secret": "shpss_[a-fA-F0-9]{32}",
		"Shopify access token": "shpat_[a-fA-F0-9]{32}",
		"Shopify custom app access token": "shpca_[a-fA-F0-9]{32}",
		"Shopify private app access token": "shppa_[a-fA-F0-9]{32}",
		"Slack token": "xox[baprs]-([0-9a-zA-Z]{10,48})?",
		"Stripe": "(sk|pk)_(test|live)_[0-9a-z]{10,32}",
		"PyPI upload token": "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}",
		"Google (GCP) Service-account": "\"type\": \"service_account\"",
		"Heroku API Key": "(heroku[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['\"]",
		"Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
		"Twilio API Key": "SK[0-9a-fA-F]{32}",
		"Age secret key": "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
		"Facebook token": "(facebook[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
		"Twitter token": "(twitter[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{35,44})['\"]",
		"Adobe Client ID (Oauth Web)": "(adobe[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
		"Adobe Client Secret": "(p8e-)[a-z0-9]{32}",
		"Alibaba AccessKey ID": "(LTAI)[a-z0-9]{20}",
		"Alibaba Secret Key": "(alibaba[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{30})['\"]",
		"Asana Client ID": "(asana[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9]{16})['\"]",
		"Asana Client Secret": "(asana[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{32})['\"]",
		"Atlassian API token": "(atlassian[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{24})['\"]",
		"Bitbucket client ID": "(bitbucket[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{32})['\"]",
		"Bitbucket client secret": "(bitbucket[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9_-]{64})['\"]",
		"Beamer API token": "(beamer[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](b_[a-z0-9=_-]{44})['\"]",
		"Clojars API token": "(CLOJARS_)[a-z0-9]{60}",
		"Contentful delivery API token": "(contentful[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9-=_]{43})['\"]",
		"Databricks API token": "dapi[a-h0-9]{32}",
		"Discord API key": "(discord[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]",
		"Discord client ID": "(discord[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9]{18})['\"]",
		"Discord client secret": "(discord[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9=_-]{32})['\"]",
		"Doppler API token": "['\"](dp\.pt\.)[a-z0-9]{43}['\"]",
		"Dropbox API secret/key": "(dropbox[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]",
		"Dropbox API secret/key": "(dropbox[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]",
		"Dropbox short lived API token": "(dropbox[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](sl\.[a-z0-9-=_]{135})['\"]",
		"Dropbox long lived API token": "(dropbox[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9-_=]{43}['\"]",
		"Duffel API token": "['\"]duffel_(test|live)_[a-z0-9_-]{43}['\"]",
		"Dynatrace API token": "['\"]dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}['\"]",
		"EasyPost API token": "['\"]EZAK[a-z0-9]{54}['\"]",
		"EasyPost test API token": "['\"]EZTK[a-z0-9]{54}['\"]",
		"Fastly API token": "(fastly[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9-=_]{32})['\"]",
		"Finicity client secret": "(finicity[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{20})['\"]",
		"Finicity API token": "(finicity[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
		"Flutterwave public key": "FLWPUBK_TEST-[a-h0-9]{32}-X",
		"Flutterwave secret key": "FLWSECK_TEST-[a-h0-9]{32}-X",
		"Flutterwave encrypted key": "FLWSECK_TEST[a-h0-9]{12}",
		"Frame.io API token": "fio-u-[a-z0-9-_=]{64}",
		"GoCardless API token": "['\"]live_[a-z0-9-_=]{40}['\"]",
		"HashiCorp Terraform user/org API token": "['\"][a-z0-9]{14}\.atlasv1\.[a-z0-9-_=]{60,70}['\"]",
		"HubSpot API token": "(hubspot[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]",
		"Intercom API token": "(intercom[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9=_]{60})['\"]",
		"Intercom client secret/ID": "(intercom[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]",
		"Ionic API token": "(ionic[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](ion_[a-z0-9]{42})['\"]",
		"Linear API token": "lin_api_[a-z0-9]{40}",
		"Linear client secret/ID": "(linear[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
		"Lob API Key": "(lob[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]((live|test)_[a-f0-9]{35})['\"]",
		"Lob Publishable API Key": "(lob[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]((test|live)_pub_[a-f0-9]{31})['\"]",
		"Mailchimp API key": "(mailchimp[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32}-us20)['\"]",
		"Mailgun private API token": "(mailgun[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](key-[a-f0-9]{32})['\"]",
		"Mailgun public validation key": "(mailgun[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](pubkey-[a-f0-9]{32})['\"]",
		"Mailgun webhook signing key": "(mailgun[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['\"]",
		"Mapbox API token": "(pk\.[a-z0-9]{60}\.[a-z0-9]{22})",
		"MessageBird API token": "(messagebird[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{25})['\"]",
		"MessageBird API client ID": "(messagebird[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]",
		"New Relic user API Key": "['\"](NRAK-[A-Z0-9]{27})['\"]",
		"New Relic user API ID": "(newrelic[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([A-Z0-9]{64})['\"]",
		"New Relic ingest browser API token": "['\"](NRJS-[a-f0-9]{19})['\"]",
		"npm access token": "['\"](npm_[a-z0-9]{36})['\"]",
		"PlanetScale password": "pscale_pw_[a-z0-9-_\.]{43}",
		"PlanetScale API token": "pscale_tkn_[a-z0-9-_\.]{43}",
		"Postman API token": "PMAK-[a-f0-9]{24}-[a-f0-9]{34}",
		"Pulumi API token": "pul-[a-f0-9]{40}",
		"Rubygem API token": "rubygems_[a-f0-9]{48}",
		"SendGrid API token": "SG\.[a-z0-9_\.-]{66}",
		"Sendinblue API token": "xkeysib-[a-f0-9]{64}-[a-z0-9]{16}",
		"Shippo API token": "shippo_(live|test)_[a-f0-9]{40}",
		"LinkedIn Client secret": "(linkedin[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z]{16})['\"]",
		"LinkedIn Client ID": "(linkedin[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{14})['\"]",
		"Twitch API token": "(twitch[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{30})['\"]",
		"Typeform API token": "(typeform[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}(tfp_[a-z0-9-_\.=]{59})",
		"Generic API Key": "((key|api[^Version]|token|secret|password|auth)[a-z0-9_ .,-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z-_=]{8,64})['\"]",
	}

	var response_body = msg.getResponseBody();

	for (var rule in rules) {
		var re = new RegExp(rules[rule], 'g');
		var findings = response_body.toString().match(re);

		if (findings) {
			for (var i in findings) {
				alert(ps, msg, rule + " was found.", findings[i]);
			}
		}
	}
}
