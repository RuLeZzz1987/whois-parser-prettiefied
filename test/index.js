const whois = require("../index");

whois.getWhois("google.com")
.then(who => console.log(who));