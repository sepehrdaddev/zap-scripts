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
var TITLE = "[" + this["zap.script.name"] + "] " + "subdomain takeover was found"
var RISK = 2 // 0: info, 1: low, 2: medium, 3: high
var CONFIDENCE = 2 // 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
var SOLUTION = "Remove the affected DNS record or Claim the domain name/Bucket."

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
		"aftership": "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.",
		"acquia": "The site you are looking for could not be found.",
		"agilecrm": "Sorry, this page is no longer available.",
		"aha": "There is no portal here ... sending you back to Aha!",
		"airee": "Ошибка 402. Сервис Айри.рф не оплачен",
		"anima": "If this is your website and you've just created it, try refreshing in a minute",
		"announcekit": "Error 404 - AnnounceKit",
		"aws-bucket": "The specified bucket does not exist",
		"bigcartel": "<h1>Oops! We couldn&#8217;t find that page.</h1>",
		"bitbucket": "Repository not found",
		"brightcove": "<p class=\"bc-gallery-error-code\">Error Code: 404</p>",
		"campaignmonitor": "<strong>Trying to access your account?</strong>",
		"canny": "Company Not Found",
		"cargocollective": "<div class=\"notfound\">",
		"cargo": "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.",
		"feedpress": "The feed has not been found.",
		"flexbe": "Domain isn't configured",
		"flywheel": "We're sorry, you've landed on a page that is hosted by Flywheel",
		"fastly": "Fastly error: unknown domain",
		"frontify": "404 - Page Not Found",
		"gemfury": "404: This page could not be found.",
		"getresponse": "With GetResponse Landing Pages, lead generation has never been easier",
		"ghost": "offline.ghost.org",
		"gitbook": "If you need specifics, here's the error",
		"github": "There isn't a GitHub Pages site here.",
		"hatenablog": "404 Blog is not found",
		"helpjuice": "We could not find what you're looking for.",
		"helprace": "Alias not configured!",
		"helpscout": "No settings were found for this company:",
		"heroku": "herokucdn.com/error-pages/no-such-app.html",
		"hubspot": "Domain not found",
		"intercom": "<h1 class=\"headline\">Uh oh. That page doesn\\’t exist.</h1>",
		"jazzhr": "This account no longer active",
		"jetbrains": "is not a registered InCloud YouTrack.",
		"kinsta": "No Site For Domain",
		"launchrock": "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.",
		"mashery": "Unrecognized domain <strong>",
		"netlify": "Not found - Request ID:",
		"ngrok": "ngrok.io not found",
		"pagewiz": "404 - Page Not Found",
		"pantheon": "The gods are wise, but do not know of the site which you seek.",
		"pingdom": "Public Report Not Activated",
		"proposify": "If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz",
		"readme": "Project doesnt exist... yet!",
		"readthedocs": "unknown to Read the Docs",
		"shopify": "To finish setting up your new web address, go to your domain settings, click \"Connect existing domain\"",
		"short-io": "Link does not exist",
		"simplebooklet": "We can't find this <a href=\"https://simplebooklet.com",
		"smartjob": "Job Board Is Unavailable",
		"smugmug": "{\"text\":\"Page Not Found\"",
		"strikingly": "But if you're looking to build your own website",
		"surge": "project not found",
		"surveygizmo": "data-html-name",
		"tave": "<h1>Error 404: Page Not Found</h1>",
		"teamwork": "Oops - We didn't find your site.",
		"tictail": "Building a brand of your own?",
		"tilda": "Please go to the site settings and put the domain name in the Domain tab.",
		"tumblr": "Whatever you were looking for doesn't currently exist at this address.",
		"uberflip": "Non-hub domain, The URL you've accessed does not provide a hub.",
		"uservoice": "This UserVoice subdomain is currently available!",
		"vend": "Looks like you've traveled too far into cyberspace.",
		"webflow": "<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>",
		"wishpond": "https://www.wishpond.com/404?campaign=true",
		"wix": "Error ConnectYourDomain occurred",
		"wordpress": "Do you want to register",
		"worksites.net": "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.</p>\n<a href=\"https://worksites.net/\">Learn more about Worksites.net",
		"wufoo": "Profile not found",
		"zendesk": "this help center no longer exists",
	}

	var response_body = msg.getResponseBody().toString();

	for (var rule in rules) {
		var evidence_idx = response_body.indexOf(rules[rule]);

		if (evidence_idx >= 0) {
			alert(ps, msg, rule + " takeover was found.", response_body.substring(evidence_idx));
		}
	}
}
