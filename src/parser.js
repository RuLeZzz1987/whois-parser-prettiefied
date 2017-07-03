const parser = require("parse-whois");
const whois = require("node-whois");
const _ = require("lodash");
const moment = require("moment");

module.exports = {
  lookup(domain) {
    return new Promise((ok, fail) => {
      whois.lookup(domain, (err, data) => {
        if (err) {
          return fail(err);
        }

        return ok(data);
      });
    });
  },

  getWhois(domain) {
    return this.lookup(domain)
      .then(whoisInfo => parser.parseWhoIsData(whoisInfo))
      .then(whoisInfo => ({
        raw: whoisInfo,
        info: whoisInfo.reduce((info, entry) => {
          const { attribute, value } = entry;
          if (attribute.includes("Domain Name")) {
            info.domainName = value;
          }
          if (attribute.includes("Registry")) {
            if (info.registry) {
              info.registry[_.camelCase(attribute)] = value;
            } else {
              info.registry = {
                [_.camelCase(attribute)]: value
              };
            }
          }
          if (attribute.includes("Registrar")) {
            if (info.registrar) {
              info.registrar[_.camelCase(attribute)] = value;
            } else {
              info.registrar = {
                [_.camelCase(attribute)]: value
              };
            }
          }
          if (attribute.includes("Updated Date")) {
            info[_.camelCase(attribute)] = moment(new Date(value)).format(
              "DD-MM-YYYY"
            );
          }
          if (attribute.includes("Creation Date")) {
            info[_.camelCase(attribute)] = moment(new Date(value)).format(
              "DD-MM-YYYY"
            );
          }
          if (attribute.includes("Domain Status")) {
            info[_.camelCase(attribute)] = value;
          }
          if (attribute.includes("Registrant")) {
            if (info.registrant) {
              info.registrant[_.camelCase(attribute)] = value;
            } else {
              info.registrant = {
                [_.camelCase(attribute)]: value
              };
            }
          }
          if (attribute.includes("Admin")) {
            if (info.admin) {
              info.admin[_.camelCase(attribute)] = value;
            } else {
              info.admin = {
                [_.camelCase(attribute)]: value
              };
            }
          }

          if (attribute.includes("Tech")) {
            if (info.tech) {
              info.tech[_.camelCase(attribute)] = value;
            } else {
              info.tech = {
                [_.camelCase(attribute)]: value
              };
            }
          }

          if (attribute.includes("Name Server")) {
            if (info.nameServer) {
              info.nameServer.push(value);
            } else {
              info.nameServer = [value];
            }
          }

          if (attribute.includes("Whois Server")) {
            info[_.camelCase(attribute)] = value;
          }

          if (_.camelCase(attribute) === "status") {
            info.status = value;
          }

          return info;
        }, {})
      }));
  }
};
