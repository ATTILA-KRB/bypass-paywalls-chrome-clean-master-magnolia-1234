'use strict';
const ext_api = typeof browser === 'object' ? browser : chrome;
const url_loc = typeof browser === 'object' ? 'firefox' : 'chrome';
const { name: ext_name, version: ext_version } = ext_api.runtime.getManifest();
const navigator_ua = navigator.userAgent.toLowerCase();
const navigator_ua_mobile = navigator_ua.includes('mobile');
const kiwi_browser = navigator_ua_mobile && url_loc === 'chrome' && !navigator_ua.includes('yabrowser') && navigator_ua.match(/chrome\/(\d+)/)[1] < 116;

ext_api.action = ext_api.action || ext_api.browserAction;

const restrictions = {
  'bloomberg.com': /^((?!\.bloomberg\.com\/news\/terminal\/).)*$/,
  'bloombergadria.com': /^((?!\.bloombergadria\.com\/video\/).)*$/,
  'dailywire.com': /^((?!\.dailywire\.com\/(episode|show|videos|watch)).)*$/,
  'economictimes.com': /\.economictimes\.com($|\/($|(__assets|prime)(\/.+)?|.+\.cms))/,
  'espn.com': /^((?!espn\.com\/watch).)*$/,
  'esquire.com': /^((?!\/classic\.esquire\.com\/).)*$/,
  'expresso.pt': /^((?!\/tribuna\.expresso\.pt\/).)*$/,
  'foreignaffairs.com': /^((?!\/reader\.foreignaffairs\.com\/).)*$/,
  'ft.com': /^((?!\/cn\.ft.com\/).)*$/,
  'hilltimes.com': /^((?!\.hilltimes\.com\/slideshow\/).)*$/,
  'hindustantimes.com': /^((?!\/epaper\.hindustantimes\.com\/).)*$/,
  'ilsole24ore.com': /^((?!\/ntplus.+\.ilsole24ore\.com\/).)*$/,
  'livemint.com': /^((?!\/epaper\.livemint\.com\/).)*$/,
  'lopinion.fr': /^((?!\.lopinion\.fr\/lejournal).)*$/,
  'mid-day.com': /^((?!\/epaper\.mid-day\.com\/).)*$/,
  'nytimes.com': /^((?!\/(help|myaccount|timesmachine)\.nytimes\.com\/).)*$/,
  'nzz.ch': /^((?!\/epaper\.nzz\.ch\/).)*$/,
  'quora.com': /^((?!quora\.com\/search\?q=).)*$/,
  'science.org': /^((?!\.science\.org\/doi\/).)*$/,
  'statista.com': /^((?!\.statista\.com\/study\/).)*$/,
  'study.com': /\/study\.com\/.+\/lesson\//,
  'tagesspiegel.de': /^((?!\/(background|checkpoint)\.tagesspiegel\.de\/).)*$/,
  'techinasia.com': /\.techinasia\.com\/.+/,
  'thetimes.co.uk': /^((?!epaper\.thetimes\.co\.uk).)*$/,
  'timeshighereducation.com': /\.timeshighereducation\.com\/((books|features|news|people)\/|.+((\w)+(\-)+){3,}.+|sites\/default\/files\/)/,
  'uol.com.br': /^((?!(conta|email|piaui\.folha)\.uol\.com\.br).)*$/,
};

au_news_corp_domains.forEach(domain => {
  restrictions[domain] = new RegExp(`^((?!todayspaper\\.${domain.replace(/\./g, '\\.')}\\/.).)*$`);
});

ch_media_domains.forEach(domain => {
  restrictions[domain] = new RegExp(`^((?!epaper\\.${domain.replace(/\./g, '\\.')}\\/.).)*$`);
});

if (typeof browser !== 'object') {
  [].forEach(domain => {
    restrictions[domain] = new RegExp(`((\\/|\\.)${domain.replace(/\./g, '\\.')}\\/$|${restrictions[domain].toString().replace(/(^\/|\/$)/g, '')})`);
  });
}

// Ne pas supprimer les cookies avant/après le chargement de la page
let allow_cookies = [];
let remove_cookies = [];
// Sélectionner des cookies spécifiques à conserver/laisser tomber des domaines remove_cookies
let remove_cookies_select_hold = {}, remove_cookies_select_drop = {};

// Définir User-Agent
let use_google_bot = [], use_bing_bot = [], use_facebook_bot = [], use_useragent_custom = [], use_useragent_custom_obj = {};
// Définir Referer
let use_facebook_referer = [], use_google_referer = [], use_twitter_referer = [], use_referer_custom = [], use_referer_custom_obj = {};
// Définir adresse IP aléatoire
let random_ip = {}, use_random_ip = [];
// Concaténer tous les sites avec changement d'en-têtes (useragent, referer ou IP aléatoire)
let change_headers = [];

// Bloquer les scripts de paywall
let blockedRegexes = {}, blockedRegexesDomains = [], blockedRegexesGeneral = {}, blockedJsInline = {}, blockedJsInlineDomains = [];

// Dévoiler le texte sur la page AMP
let amp_unhide, amp_redirect, cs_block, cs_clear_lclstrg, cs_code;
// Charger le texte depuis json (script[type="application/ld+json"])
let ld_json = {}, ld_json_next = {}, ld_json_url = {}, ld_archive_is = {}, ld_google_webcache = {}, add_ext_link = {};

// Personnalisé : bloquer javascript
let block_js_custom = [], block_js_custom_ext = [];

function initSetRules() {
  const resetValues = () => ({
    allow_cookies: [],
    remove_cookies: [],
    remove_cookies_select_drop: {},
    remove_cookies_select_hold: {},
    use_google_bot: [],
    use_bing_bot: [],
    use_facebook_bot: [],
    use_useragent_custom: [],
    use_useragent_custom_obj: {},
    use_facebook_referer: [],
    use_google_referer: [],
    use_twitter_referer: [],
    use_referer_custom: [],
    use_referer_custom_obj: {},
    random_ip: {},
    change_headers: [],
    amp_unhide: [],
    amp_redirect: {},
    cs_block: {},
    cs_clear_lclstrg: [],
    cs_code: {},
    ld_json: {},
    ld_json_next: {},
    ld_json_url: {},
    ld_archive_is: {},
    ld_google_webcache: {},
    add_ext_link: {},
    block_js_custom: [],
    block_js_custom_ext: [],
    blockedRegexes: {},
    blockedRegexesDomains: [],
    blockedRegexesGeneral: {},
    blockedJsInline: {},
    blockedJsInlineDomains: []
  });

  Object.assign(this, resetValues());
  init_custom_flex_domains();

const userAgents = {
  desktopG: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  mobileG: "Chrome/115.0.5790.171 Mobile Safari/537.36 (compatible ; Googlebot/2.1 ; +http://www.google.com/bot.html)",
  desktopB: "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  mobileB: "Chrome/115.0.5790.171 Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  desktopF: 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
};

let sites = {
  enabled: [],
  disabled: [],
  options: {},
  custom: {},
  customDomains: [],
  updated: {},
  updatedNew: [],
  updatedDomainsNew: [],
  excluded: []
};

function setDefaultOptions() {
  ext_api.storage.local.set({
    sites: filterObject(defaultSites, (val, key) => 
      val.domain && !val.domain.match(/^(###$|#options_(disable|optin)_)/),
      (val, key) => [key, val.domain]
    )
  }, () => {
    ext_api.runtime.openOptionsPage();
  });
}

function check_sites_updated(sites_updated_json, optin_update = false) {
  fetch(sites_updated_json)
    .then(response => {
      if (!response.ok) return;
      return response.json();
    })
    .then(json => {
      json = filterObject(json, (val) => 
        val.domain && !(val.upd_version && (val.upd_version <= ext_version))
      );
      expandSiteRules(json, true);
      ext_api.storage.local.set({ sites_updated: json });
      if (!optin_update) {
        const updated_ext_version_new = Object.values(json)
          .map(x => x.upd_version || '')
          .sort()
          .pop();
        if (updated_ext_version_new) setExtVersionNew(updated_ext_version_new);
      }
    })
    .catch(err => console.error(`Error fetching sites updated: ${err}`));
}

const ext_path = 'https://gitflic.ru/project/magnolia1234/bpc_updates/blob/raw?file=';
const sites_updated_json = 'sites_updated.json';
const sites_updated_json_online = `${ext_path}${sites_updated_json}`;
const self_hosted = !!(manifestData.update_url || manifestData.browser_specific_settings?.gecko?.update_url);

function clear_sites_updated() {
  ext_api.storage.local.set({ sites_updated: {} });
}

function prep_regex_str(str, domain = '') {
  return str.replace(/{domain}/g, domain.replace(/\./g, '\\.'))
            .replace(/^\//, '')
            .replace(/\/\//g, '/')
            .replace(/([^\\])\/$/, "$1");
}

function addRules(domain, rule) {
  const { remove_cookies, allow_cookies, block_regex, block_regex_general, block_js_inline, useragent, useragent_custom, referer, referer_custom, random_ip, amp_unhide, amp_redirect, cs_block, cs_code, ld_json, ld_json_next, ld_json_url, ld_archive_is, ld_google_webcache, cs_dompurify, add_ext_link, add_ext_link_type } = rule;

  if (remove_cookies > 0 || rule.remove_cookies_select_hold || !(allow_cookies || rule.remove_cookies_select_drop) || rule.cs_clear_lclstrg) {
    cs_clear_lclstrg.push(domain);
  }

  if (remove_cookies_select_drop || remove_cookies_select_hold) {
    rule.allow_cookies = 1;
    rule.remove_cookies = 1;
  }

  if (allow_cookies > 0 && !allow_cookies.includes(domain)) {
    allow_cookies.push(domain);
  }

  if (remove_cookies > 0 && !remove_cookies.includes(domain)) {
    remove_cookies.push(domain);
  }

  if (rule.remove_cookies_select_drop) {
    remove_cookies_select_drop[domain] = rule.remove_cookies_select_drop;
  }

  if (rule.remove_cookies_select_hold) {
    remove_cookies_select_hold[domain] = rule.remove_cookies_select_hold;
  }

  const handleRegex = (regex, target) => {
    if (regex instanceof RegExp) {
      target[domain] = regex;
    } else {
      try {
        target[domain] = new RegExp(prep_regex_str(regex, domain));
      } catch (e) {
        console.log(`regex not valid, error: ${e}`);
      }
    }
  };

  if (block_regex) handleRegex(block_regex, blockedRegexes);
  if (block_regex_general) {
    handleRegex(block_regex_general, blockedRegexesGeneral);
    blockedRegexesGeneral[domain]['excluded_domains'] = rule.excluded_domains || [];
  }
  if (block_js_inline) handleRegex(block_js_inline, blockedJsInline);

  const addToList = (list, value) => {
    if (!list.includes(domain)) list.push(domain);
  };

  if (useragent) {
    const useragents = {
      'googlebot': use_google_bot,
      'bingbot': use_bing_bot,
      'facebookbot': use_facebook_bot
    };
    addToList(useragents[useragent], domain);
  } else if (useragent_custom) {
    addToList(use_useragent_custom, domain);
    use_useragent_custom_obj[domain] = useragent_custom;
  }

  if (referer) {
    const referers = {
      'facebook': use_facebook_referer,
      'google': use_google_referer,
      'twitter': use_twitter_referer
    };
    addToList(referers[referer], domain);
  } else if (referer_custom) {
    addToList(use_referer_custom, domain);
    use_referer_custom_obj[domain] = referer_custom;
  }

  if (random_ip) random_ip[domain] = random_ip;
  if (amp_unhide > 0) addToList(amp_unhide, domain);
  if (amp_redirect) amp_redirect[domain] = amp_redirect;
  if (cs_block) cs_block[domain] = 1;

  if (cs_code) {
    if (typeof cs_code === 'string') {
      try {
        rule.cs_code = JSON.parse(cs_code);
      } catch (e) {
        console.log(`cs_code not valid: ${cs_code} error: ${e}`);
      }
    }
    if (typeof rule.cs_code === 'object') cs_code[domain] = rule.cs_code;
  }

  if (ld_json) ld_json[domain] = ld_json;
  if (ld_json_next) ld_json_next[domain] = ld_json_next;
  if (ld_json_url) ld_json_url[domain] = ld_json_url;
  if (ld_archive_is) ld_archive_is[domain] = ld_archive_is;
  if (ld_google_webcache) ld_google_webcache[domain] = ld_google_webcache;

  if (ld_json || ld_json_next || ld_json_url || ld_archive_is || ld_google_webcache || cs_dompurify) {
    addToList(dompurify_sites, domain);
  }

  if (add_ext_link && add_ext_link_type) {
    add_ext_link[domain] = { css: add_ext_link, type: add_ext_link_type };
  }

  if (rule.block_js > 0) addToList(block_js_custom, domain);
  if (rule.block_js_ext > 0) addToList(block_js_custom_ext, domain);
}

function customFlexAddRules(custom_domain, rule) {
  addRules(custom_domain, rule);
  if (blockedRegexes[custom_domain])
    blockedRegexesDomains.push(custom_domain);
  if (blockedJsInline[custom_domain]) {
    blockedJsInlineDomains.push(custom_domain);
    disableJavascriptInline();
  }
  if (rule.useragent || rule.useragent_custom || rule.referer || rule.referer_custom || rule.random_ip)
    change_headers.push(custom_domain);
  if (rule.random_ip)
    use_random_ip.push(custom_domain);
  ext_api.tabs.reload({bypassCache: true});
}

function set_rules(sites, sites_updated, sites_custom) {
  initSetRules();
  for (let site in sites) {
    let site_domain = sites[site].toLowerCase();
    let custom = false;
    if (!site_domain.match(/^(###$|#options_)/)) {
      let rule = {};
      let site_default = defaultSites.hasOwnProperty(site) ? site : Object.keys(defaultSites).find(default_key => compareKey(default_key, site));
      if (site_default) {
        rule = defaultSites[site_default];
        let site_updated = Object.keys(sites_updated).find(updated_key => compareKey(updated_key, site));
        if (site_updated) {
          rule = sites_updated[site_updated];
          if (rule.nofix) {
            enabledSites.splice(enabledSites.indexOf(site_domain), 1);
            nofix_sites.push(site_domain);
          }
        }
      } else if (sites_updated.hasOwnProperty(site)) { // updated (new) sites
        rule = sites_updated[site];
      } else if (sites_custom.hasOwnProperty(site)) { // custom (new) sites
        rule = sites_custom[site];
        custom = true;
      } else
        continue;
      let domains = [site_domain];
      let group = false;
      if (rule.hasOwnProperty('group')) {
        domains = (typeof rule.group !== 'string') ? rule.group : rule.group.split(',');
        group = true;
      }
      let rule_default = {};
      if (rule.hasOwnProperty('exception')) {
        for (let key in rule)
          rule_default[key] = rule[key];
      }
      for (let domain of domains) {
        let custom_in_group = false;
        if (rule_default.hasOwnProperty('exception')) {
          let exception_rule = rule_default.exception.filter(x => domain === x.domain || (typeof x.domain !== 'string' && x.domain.includes(domain)));
          if (exception_rule.length > 0)
            rule = exception_rule[0];
          else
            rule = rule_default;
        }
        // custom domain for default site(group)
        if (!custom) {
          let isCustomSite = matchDomain(customSites_domains, domain);
          let customSite_title = isCustomSite ? Object.keys(customSites).find(key => customSites[key].domain === isCustomSite) : '';
          if (customSite_title && !(sites_custom[customSite_title].add_ext_link || customSitesExt_remove.includes(isCustomSite))) {
            // add default block_regex
            let block_regex_default = '';
            if (rule.hasOwnProperty('block_regex'))
              block_regex_default = rule.block_regex;
            rule = {};
            for (let key in sites_custom[customSite_title])
              rule[key] = sites_custom[customSite_title][key];
            if (block_regex_default && !rule.block_regex_ignore_default) {
              if (rule.hasOwnProperty('block_regex')) {
                if (block_regex_default instanceof RegExp)
                  block_regex_default = block_regex_default.source;
                rule.block_regex = '(' + block_regex_default + '|' + prep_regex_str(rule.block_regex, domain) + ')';
              } else
                rule.block_regex = block_regex_default;
            }
            if (group)
              custom_in_group = true;
            else
              custom = true;
          }
        }
        addRules(domain, rule);
      }
    }
  }
  blockedRegexesDomains = Object.keys(blockedRegexes);
  blockedJsInlineDomains = Object.keys(blockedJsInline);
  disableJavascriptInline();
  use_random_ip = Object.keys(random_ip);
  change_headers = use_google_bot.concat(use_bing_bot, use_facebook_bot, use_useragent_custom, use_facebook_referer, use_google_referer, use_twitter_referer, use_referer_custom, use_random_ip);
}

// add grouped sites to en/disabledSites (and exclude sites)
function add_grouped_enabled_domains(groups) {
  for (let key in groups) {
    if (enabledSites.includes(key))
      enabledSites = enabledSites.concat(groups[key]);
    else
      disabledSites = disabledSites.concat(groups[key]);
  }
  // custom
  for (let site in customSites) {
    let group = customSites[site].group;
    if (group) {
      let group_array = group.split(',');
      if (enabledSites.includes(customSites[site].domain))
        enabledSites = enabledSites.concat(group_array);
      else
        disabledSites = disabledSites.concat(group_array);
    }
  }
  for (let site of excludedSites) {
    if (enabledSites.includes(site)) {
      enabledSites.splice(enabledSites.indexOf(site), 1);
      disabledSites.push(site);
    }
  }
}

// Get the enabled sites (from local storage) & set_rules for sites
ext_api.storage.local.get({
  sites: {},
  sites_default: Object.keys(defaultSites).filter(x => defaultSites[x].domain && !/^#options_|###$/.test(defaultSites[x].domain)),
  sites_custom: {},
  sites_updated: {},
  sites_excluded: [],
  ext_version_old: '2.3.9.0',
  optIn: false,
  optInUpdate: true
}, function (items) {
  const { sites, sites_default, sites_custom, sites_updated, ext_version_old, optIn, optInUpdate, sites_excluded } = items;

  optionSites = sites;
  customSites = filterObject(sites_custom, val => !(val.add_ext_link && !val.add_ext_link_type));
  customSites_domains = Object.values(customSites).flatMap(x => x.group ? [...x.group.split(',').map(x => x.trim()), x.domain] : x.domain);
  
  updatedSites_domains_new = Object.values(sites_updated).flatMap(x => 
    x.domain && !defaultSites_domains.includes(x.domain) || x.group ? 
    (x.group ? x.group.filter(y => !defaultSites_domains.includes(y)).concat(x.domain) : x.domain) : []
  );

  optin_setcookie = optIn;
  optin_update = optInUpdate;
  excludedSites = sites_excluded;

  enabledSites = Object.values(sites).filter(val => val && val !== '###' && 
    defaultSites_domains.concat(customSites_domains, updatedSites_domains_new).includes(val)
  ).map(val => val.toLowerCase());

  // Enable new sites by default (opt-in)
  updatedSites_new = Object.keys(updatedSites).filter(x => updatedSites[x].domain && !defaultSites_domains.includes(updatedSites[x].domain));
  Object.entries(updatedSites).forEach(([site_updated, site_data]) => {
    defaultSites[site_updated] = site_data;
    if (site_data.group) {
      grouped_sites[site_data.domain] = site_data.group;
    }
  });

  if (ext_version > ext_version_old || updatedSites_new.length > 0) {
    if (enabledSites.includes('#options_enable_new_sites')) {
      const sites_new = Object.keys(defaultSites).filter(x => 
        defaultSites[x].domain && 
        !/^#options_|###$/.test(defaultSites[x].domain) && 
        !sites_default.some(key => compareKey(key, x))
      );

      sites_new.forEach(site_new => {
        sites[site_new] = defaultSites[site_new].domain;
      });

      // reset ungrouped sites
      const ungrouped_sites = {
        'The Stage Media (UK)': '###_uk_thestage_media',
        'The Week (regwall)': 'theweek.com'
      };

      Object.entries(ungrouped_sites).forEach(([key, value]) => {
        if (sites[key] && sites[key] !== value) {
          sites[key] = value;
        }
      });

      ext_api.storage.local.set({ sites });
    } else {
      ext_api.management.getSelf(result => {
        if (result.installType === 'development' || 
            (result.installType !== 'development' && !enabledSites.includes('#options_on_update'))) {
          const new_groups = ['###_au_private_media', '###_ch_ringier', '###_fr_groupe_infopro', '###_pl_ringier', '###_usa_digiday'];
          const open_options = new_groups.some(group => 
            !enabledSites.includes(group) && 
            grouped_sites[group].some(domain => enabledSites.includes(domain) && !customSites_domains.includes(domain))
          );

          if (open_options) {
            ext_api.runtime.openOptionsPage();
          }
        }
      });
    }
  }
    sites_default = Object.keys(defaultSites).filter(x => defaultSites[x].domain && !defaultSites[x].domain.match(/^(#options_|###$)/));
    ext_api.storage.local.set({
      sites_default: sites_default,
      ext_version_old: ext_version
    });
  }
  disabledSites = [...new Set([...defaultSites_grouped_domains, ...customSites_domains, ...updatedSites_domains_new].filter(x => !enabledSites.includes(x)))];
  add_grouped_enabled_domains(grouped_sites);
  set_rules(sites, updatedSites, customSites);
  if (optin_update) check_update();
  if (enabledSites.includes('#options_optin_update_rules') && self_hosted) {
    sites_updated_json = sites_updated_json_online;
    sites_custom_ext_json = `${ext_path}sites_custom.json`;
  }
  check_sites_updated(sites_updated_json, optin_update);
  check_sites_custom_ext();
  if (!Object.keys(sites).length) ext_api.runtime.openOptionsPage();

// Listen for changes to options
ext_api.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'sync') return;

  for (const key in changes) {
    const storageChange = changes[key];

    switch (key) {
      case 'sites': {
        const sites = storageChange.newValue;
        optionSites = sites;
        enabledSites = Object.values(sites)
          .filter(val => val && val !== '###' && (defaultSites_domains.concat(customSites_domains, updatedSites_domains_new).includes(val)))
          .map(val => val.toLowerCase());

        disabledSites = defaultSites_grouped_domains.concat(customSites_domains, updatedSites_domains_new)
          .filter(x => !enabledSites.includes(x));

        add_grouped_enabled_domains(grouped_sites);
        set_rules(sites, updatedSites, customSites);
        break;
      }
      case 'sites_custom': {
        const sites_custom = storageChange.newValue || {};
        const sites_custom_old = storageChange.oldValue || {};
        customSites = sites_custom;
        customSites_domains = Object.values(sites_custom)
          .flatMap(x => x.group ? x.group.split(',').map(x => x.trim()).concat([x.domain]) : x.domain);

        const sites_custom_added = Object.keys(sites_custom)
          .filter(x => !Object.keys(sites_custom_old).includes(x) && !defaultSites.hasOwnProperty(x) && !defaultSites_domains.includes(sites_custom[x].domain));

        const sites_custom_removed = Object.keys(sites_custom_old)
          .filter(x => !Object.keys(sites_custom).includes(x) && !defaultSites.hasOwnProperty(x) && !defaultSites_domains.includes(sites_custom_old[x].domain));

        ext_api.storage.local.get({ sites: {} }, items => {
          const sites = items.sites;

          if (sites_custom_added.length || sites_custom_removed.length) {
            sites_custom_added.forEach(key => sites[key] = sites_custom[key].domain);
            sites_custom_removed.forEach(key => delete sites[key]);

            ext_api.storage.local.set({ sites }, () => true);
          } else {
            set_rules(sites, updatedSites, customSites);
          }
        });
        break;
      }
      case 'sites_updated': {
        const sites_updated = storageChange.newValue || {};
        updatedSites = sites_updated;
        updatedSites_domains_new = Object.values(updatedSites)
          .filter(x => (x.domain && !defaultSites_domains.includes(x.domain) || x.group))
          .flatMap(x => x.group ? x.group.filter(y => !defaultSites_domains.includes(y)) : x.domain);

        const updatedSites_new = Object.keys(updatedSites)
          .filter(x => updatedSites[x].domain && !defaultSites_domains.includes(updatedSites[x].domain));

        if (updatedSites_new.length > 0 && enabledSites.includes('#options_enable_new_sites')) {
          updatedSites_new.forEach(site_updated_new => optionSites[site_updated_new] = updatedSites[site_updated_new].domain);
          ext_api.storage.local.set({ sites: optionSites });
        } else {
          set_rules(optionSites, updatedSites, customSites);
        }
        break;
      }
      case 'sites_excluded': {
        const sites_excluded = storageChange.newValue || [];
        const sites_excluded_old = storageChange.oldValue || [];
        excludedSites = sites_excluded;

        const sites_excluded_added = sites_excluded.filter(x => !sites_excluded_old.includes(x));
        const sites_excluded_removed = sites_excluded_old.filter(x => !sites_excluded.includes(x));

        sites_excluded_added.forEach(site => {
          if (enabledSites.includes(site)) {
            enabledSites.splice(enabledSites.indexOf(site), 1);
            disabledSites.push(site);
          }
        });

        sites_excluded_removed.forEach(site => {
          if (disabledSites.includes(site)) {
            disabledSites.splice(disabledSites.indexOf(site), 1);
            enabledSites.push(site);
          }
        });
        break;
      }
      case 'ext_version_new':
        ext_version_new = storageChange.newValue;
        break;
      case 'optIn':
        optin_setcookie = storageChange.newValue;
        break;
      case 'optInUpdate':
        optin_update = storageChange.newValue;
        break;
    }
  }
});

// Set and show default options on install
ext_api.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") {
    setDefaultOptions();
  } else if (reason === "update") {
    ext_api.management.getSelf(result => {
      if (enabledSites.includes('#options_on_update') && result.installType !== 'development') {
        ext_api.runtime.openOptionsPage(); // L'utilisateur a mis à jour l'extension (mode non-développeur)
      }
    });
  }
});

// Google AMP cache redirect
ext_api.webRequest.onBeforeRequest.addListener((details) => {
  const url = details.url.split('?')[0];
  let updatedUrl;

  if (matchUrlDomain('cdn.ampproject.org', url)) {
    updatedUrl = `https://${url.split(/cdn\.ampproject\.org\/[a-z]\/s\//)[1]}`;
  } else if (matchUrlDomain('google.com', url)) {
    updatedUrl = `https://${url.split(/\.google\.com\/amp\/s\//)[1]}`;
  }

  return { redirectUrl: decodeURIComponent(updatedUrl) };
}, {
  urls: ["*://*.cdn.ampproject.org/*/s/*", "*://*.google.com/amp/s/*"],
  types: ["main_frame"]
}, ["blocking"]);

// inkl bypass
ext_api.webRequest.onBeforeRequest.addListener(function (details) {
  if (!isSiteEnabled(details)) {
    return;
  }
  var updatedUrl = details.url.replace(/etok=[\w]*&/, '');
  if (details.url.includes('/signin?') && details.url.includes('redirect_to='))
    updatedUrl = 'https://www.inkl.com' + decodeURIComponent(updatedUrl.split('redirect_to=')[1]);
  return { redirectUrl: updatedUrl };
},
{urls:["*://*.inkl.com/*"], types:["main_frame"]},
["blocking"]
);

const userAgentMobile = "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Mobile Safari/537.36";

// Définir l'agent utilisateur pour webcache.googleusercontent.com (sur Firefox pour Android)
if (typeof browser === 'object' && navigator_ua_mobile) {
  ext_api.webRequest.onBeforeSendHeaders.addListener((details) => {
    const headers = details.requestHeaders.map(header => {
      if (header.name.toLowerCase() === 'user-agent') {
        header.value = userAgentMobile;
      }
      return header;
    });
    return { requestHeaders: headers };
  }, {
    urls: ["*://webcache.googleusercontent.com/*"],
    types: ["main_frame", "xmlhttprequest"]
  }, ["blocking", "requestHeaders"]);
}

// Australia News Corp redirect subscribe to amp
const auNewsCorpNoAmpFix = ['ntnews.com.au'];
const auNewsCorpSubscr = au_news_corp_domains
  .filter(domain => !auNewsCorpNoAmpFix.includes(domain))
  .map(domain => `*://www.${domain}/subscribe/*`);

ext_api.webRequest.onBeforeRequest.addListener(details => {
  if (!isSiteEnabled(details) || details.url.includes('/digitalprinteditions') || !details.url.includes('dest=')) {
    return;
  }
  
  const destParam = details.url.split('dest=')[1].split('&')[0];
  if (!destParam) {
    return;
  }

  const updatedUrl = decodeURIComponent(destParam) + '?amp';
  return { redirectUrl: updatedUrl };
}, {
  urls: auNewsCorpSubscr,
  types: ["main_frame"]
}, ["blocking"]);

// fix nytimes x-frame-options (hidden iframe content)
ext_api.webRequest.onHeadersReceived.addListener(function (details) {
  if (!isSiteEnabled(details)) {
    return;
  }
  var headers = details.responseHeaders;
  headers = headers.map(function (header) {
      if (header.name === 'x-frame-options')
        header.value = 'SAMEORIGIN';
      return header;
    });
  return {
    responseHeaders: headers
  };
}, {
  urls: ["*://*.nytimes.com/*"]
},
  ['blocking', 'responseHeaders']);

function blockJsInlineListener(details) {
  let domain = matchUrlDomain(blockedJsInlineDomains, details.url);
  let matched = domain && details.url.match(blockedJsInline[domain]);
  if (matched && optin_setcookie && ['uol.com.br'].includes(domain))
    matched = false;
  if (!isSiteEnabled(details) || !matched)
    return;
  var headers = details.responseHeaders;
  headers.push({
    'name': 'Content-Security-Policy',
    'value': "script-src *;"
  });
  return {
    responseHeaders: headers
  };
}

function disableJavascriptInline() {
  // Bloquer les scripts en ligne
  ext_api.webRequest.onHeadersReceived.removeListener(blockJsInlineListener);
  
  const blockJsInlineUrls = Object.keys(blockedJsInline).map(domain => `*://*.${domain}/*`);
  
  if (blockJsInlineUrls.length) {
    ext_api.webRequest.onHeadersReceived.addListener(blockJsInlineListener, {
      types: ['main_frame', 'sub_frame'],
      urls: blockJsInlineUrls
    }, ['blocking', 'responseHeaders']);
  }
}

if (typeof browser !== 'object') {
  var focus_changed = false;
  ext_api.windows.onFocusChanged.addListener((windowId) => {
    if (windowId > 0)
      focus_changed = true;
  });
}

  function runOnTab(tab) {
    const tabId = tab.id;
    const url = tab.url;
    const rc_domain = matchUrlDomain(remove_cookies, url);
    const rc_domain_enabled = rc_domain && enabledSites.includes(rc_domain);
    const lib_file = matchUrlDomain(dompurify_sites, url) ? 'lib/purify.min.js' : 'lib/empty.js';
    const bg2csData = {};

    if (optin_setcookie && matchUrlDomain(['###'], url)) bg2csData.optin_setcookie = 1;
    if (matchUrlDomain(amp_unhide, url)) bg2csData.amp_unhide = 1;

    const domains = [
      { key: 'amp_redirect', domain: amp_redirect },
      { key: 'cs_clear_lclstrg', domain: cs_clear_lclstrg },
      { key: 'cs_code', domain: cs_code },
      { key: 'ld_json', domain: ld_json },
      { key: 'ld_json_next', domain: ld_json_next },
      { key: 'ld_json_url', domain: ld_json_url },
      { key: 'ld_archive_is', domain: ld_archive_is },
      { key: 'ld_google_webcache', domain: ld_google_webcache },
      { key: 'add_ext_link', domain: add_ext_link }
    ];

    domains.forEach(({ key, domain }) => {
      const domain_match = matchUrlDomain(Object.keys(domain),
            return;
          ext_api.tabs.executeScript(tabId, {
              console.error(err);
            file: 'contentScript.js',
            runAt: 'document_start'
          }, function (res) {
            if (ext_api.runtime.lastError || res[0]) {
      }
      // remove cookies after page load
      if (rc_domain_enabled && !['enotes.com', 'huffingtonpost.it', 'lastampa.it'].includes(rc_domain)) {
        remove_cookies_fn(rc_domain, true);
      }
    }, n * 200);
              return;
            }
          })
        });
        // send bg2csData to contentScript.js
        if (Object.keys(bg2csData).length) {
          setTimeout(function () {
            try {
}

function executeScriptsSequentially(tabId, scripts) {
  const executeScript = (file) => ext_api.tabs.executeScript(tabId, {file, runAt: 'document_start'}, () => {
    if (ext_api.runtime.lastError) {
      console.error(`Error executing script: ${file}`, ext_api.runtime.lastError.message);
    }
  });

  scripts.forEach(script => executeScript(script));
}
/******  e193ac41-f726-4a10-b80d-6ac8fef85c28  *******/
              ext_api.tabs.sendMessage(tabId, {msg: "bg2cs", data: bg2csData});
            } catch (err) {
              false;
            }
          }, 500);
        }
        } // !cs_block_domain
        // remove cookies after page load
        if (rc_domain_enabled && !['enotes.com', 'huffingtonpost.it', 'lastampa.it'].includes(rc_domain)) {
          remove_cookies_fn(rc_domain, true);
        }
      }, n * 200);
    }
  }

  function runOnTabOnce(tab) {
    const { id: tabId, url } = tab;

    // Charger contentScript_once.js pour identifier le site personnalisé (flex) du groupe
    const allCustomDomains = custom_flex_domains.concat(custom_flex_not_domains, customSites_domains, updatedSites_domains_new, excludedSites, nofix_sites);
    if (!matchUrlDomain(allCustomDomains, url) && !matchUrlDomain(defaultSites_domains, url)) {
      ext_api.tabs.executeScript(tabId, {
        file: 'contentScript_once.js',
        runAt: 'document_start'
      }, (res) => {
        if (ext_api.runtime.lastError || res[0]) {
          return;
        }
      });
    }

    // Charger toggleIcon.js (icône pour le mode sombre ou incognito dans Chrome)
    if (typeof browser !== 'object') {
      ext_api.tabs.executeScript(tabId, {
        file: 'options/toggleIcon.js',
        runAt: 'document_start'
      }, (res) => {
        if (ext_api.runtime.lastError || res[0]) {
          return;
        }
      });
    }
  }

  const setVarSites = ['dagsavisen.no', 'journaldemontreal.com', 'journaldequebec.com', 'nzherald.co.nz'].concat(de_madsack_domains);
  function runOnTabOnceVar(tab) {
    const { id: tabId, url } = tab;
    const domain = matchUrlDomain(setVarSites, url);

    // Charger contentScript_once_var.js pour définir des variables pour le site
    if (domain && enabledSites.includes(domain)) {
      ext_api.tabs.executeScript(tabId, {
        file: 'contentScript_once_var.js',
        runAt: 'document_start'
      }, (res) => {
        if (ext_api.runtime.lastError || res[0]) {
          return;
        }
      });
    }
  }

ext_api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  let tab_status = changeInfo.status;
  if (/^http/.test(tab.url)) {
    if ((tab_status && (tab_status === 'complete' || matchUrlDomain(['startribune.com'], tab.url))) || changeInfo.url) {
      let timeout = changeInfo.url ? 500 : 0;
      setTimeout(function () {
        if (isSiteEnabled(tab)) {
          runOnTab(tab);
        }
        runOnTab_once(tab);
      }, timeout);
    }
    runOnTab_once_var(tab);
  }
});

const extraInfoSpec = ['blocking', 'requestHeaders'];
if (ext_api.webRequest.OnBeforeSendHeadersOptions.hasOwnProperty('EXTRA_HEADERS')) {
  extraInfoSpec.push('extraHeaders');
}

ext_api.webRequest.onBeforeSendHeaders.addListener((details) => {
  const requestHeaders = details.requestHeaders;

  let headerReferer = details.originUrl || '';
  if (!headerReferer) {
    headerReferer = requestHeaders.find(header => header.name.toLowerCase() === 'referer')?.value || '';
  }

  const blockedRefererDomains = ['timeshighereducation.com'];
  if (!headerReferer && details.initiator) {
    headerReferer = details.initiator;
    if (matchUrlDomain(blockedRefererDomains, details.url) && ['script', 'xmlhttprequest'].includes(details.type)) {
      blockedRefererDomains.forEach(domain => {
        restrictions[domain] = new RegExp(`((\\/|\\.)${domain.replace(/\./g, '\\.')}(\\$|\\/$)|${restrictions[domain].toString().replace(/(^\/|\/$)/g, '')})`);
      });
    }
  }

  // block external javascript for custom sites (optional)
  if (['script'].includes(details.type)) {
    let domain_blockjs_ext = matchUrlDomain(block_js_custom_ext, header_referer);
    if (domain_blockjs_ext && !matchUrlDomain(domain_blockjs_ext, details.url) && isSiteEnabled({url: header_referer}))
      return { cancel: true };
  }

  // check for blocked regular expression: domain enabled, match regex, block on an internal or external regex
  if (['script', 'xmlhttprequest'].includes(details.type)) {
    let domain = matchUrlDomain(blockedRegexesDomains, header_referer);
    if (domain && details.url.match(blockedRegexes[domain]) && isSiteEnabled({url: header_referer}))
      return { cancel: true };
  }

  // block general paywall scripts
  if (['script', 'xmlhttprequest'].includes(details.type)) {
    for (let domain in blockedRegexesGeneral) {
      if (details.url.match(blockedRegexesGeneral[domain].block_regex) && !(matchUrlDomain(excludedSites.concat(disabledSites, blockedRegexesGeneral[domain].excluded_domains), header_referer)))
        return { cancel: true };
    }
  }

  if (!isSiteEnabled(details)) {
    return;
  }

  // block javascript of (sub)domain for custom sites (optional)
  const domainBlockJs = matchUrlDomain(block_js_custom, details.url);
  if (domainBlockJs && details.type === 'script') {
    return { cancel: true };
  }

  let useUserAgentMobile = false;
  let setReferer = false;

  const ignoreTypes = matchUrlDomain(au_news_corp_domains, details.url) 
    ? ['font', 'image', 'stylesheet', 'other', 'script', 'xmlhttprequest'] 
    : ['font', 'image', 'stylesheet'];

  if (matchUrlDomain(change_headers, details.url) && !ignoreTypes.includes(details.type)) {
    const mobile = details.requestHeaders.some(x => x.name.toLowerCase() === "user-agent" && x.value.toLowerCase().includes("mobile"));
    const googlebotEnabled = matchUrlDomain(use_google_bot, details.url) && 
      !(matchUrlDomain(es_grupo_vocento_domains, details.url) && mobile) &&
      !(matchUrlDomain(['economictimes.com', 'economictimes.indiatimes.com'], details.url) && !details.url.split(/\?|#/)[0].endsWith('.cms')) &&
      !(matchUrlDomain(au_news_corp_domains, details.url) && (details.url.includes('?amp') || (!matchUrlDomain(au_news_corp_no_amp_fix, details.url) && enabledSites.includes('#options_disable_gb_au_news_corp')))) &&
      !(matchUrlDomain('nytimes.com', details.url) && details.url.includes('.nytimes.com/live/')) &&
      !(matchUrlDomain('uol.com.br', details.url) && !matchUrlDomain('folha.uol.com.br', details.url));
    const bingbotEnabled = matchUrlDomain(use_bing_bot, details.url);
    const facebookbotEnabled = matchUrlDomain(use_facebook_bot, details.url);
    const useragentCustomEnabled = matchUrlDomain(use_useragent_custom, details.url);

    // if referer exists, set it
    requestHeaders = requestHeaders.map(requestHeader => {
      if (requestHeader.name === 'Referer') {
        if (googlebotEnabled || matchUrlDomain(use_google_referer, details.url)) {
          requestHeader.value = 'https://www.google.com/';
        } else if (matchUrlDomain(use_facebook_referer, details.url)) {
          requestHeader.value = 'https://www.facebook.com/';
        } else if (matchUrlDomain(use_twitter_referer, details.url)) {
          requestHeader.value = 'https://t.co/';
        } else if (domain = matchUrlDomain(use_referer_custom, details.url)) {
          requestHeader.value = use_referer_custom_obj[domain];
        }
        setReferer = true;
      }
      if (requestHeader.name === 'User-Agent') {
        useUserAgentMobile = (requestHeader.value.toLowerCase().includes("mobile") || matchUrlDomain(au_news_corp_domains, details.url)) && !matchUrlDomain(['telerama.fr', 'theatlantic.com'], details.url);
      }
      return requestHeader;
    });
  }

  // otherwise add it
  if (!setReferer) {
    if (googlebotEnabled || matchUrlDomain(use_google_referer, details.url)) {
      requestHeaders.push({
        name: 'Referer',
        value: 'https://www.google.com/'
      });
    } else if (matchUrlDomain(use_facebook_referer, details.url)) {
      requestHeaders.push({
        name: 'Referer',
        value: 'https://www.facebook.com/'
      });
    } else if (matchUrlDomain(use_twitter_referer, details.url)) {
      requestHeaders.push({
        name: 'Referer',
        value: 'https://t.co/'
      });
    } else if (domain = matchUrlDomain(use_referer_custom, details.url)) {
      requestHeaders.push({
        name: 'Referer',
        value: use_referer_custom_obj[domain]
      });
    }
  }

  const userAgentMap = {
    googlebot: useUserAgentMobile ? userAgentMobileG : userAgentDesktopG,
    bingbot: useUserAgentMobile ? userAgentMobileB : userAgentDesktopB,
    facebookbot: userAgentDesktopF,
    custom: domain => use_useragent_custom_obj[domain]
  };

  if (googlebotEnabled) {
    requestHeaders.push({ "name": "User-Agent", "value": userAgentMap.googlebot });
    requestHeaders.push({ "name": "X-Forwarded-For", "value": "66.249.66.1" });
  } else if (bingbotEnabled) {
    requestHeaders.push({ "name": "User-Agent", "value": userAgentMap.bingbot });
  } else if (facebookbotEnabled) {
    requestHeaders.push({ "name": "User-Agent", "value": userAgentMap.facebookbot });
  } else if (useragent_customEnabled) {
    requestHeaders.push({ "name": "User-Agent", "value": userAgentMap.custom(useragent_customEnabled) });
  }

  const domain_random = matchUrlDomain(use_random_ip, details.url);
  if (domain_random && !googlebotEnabled) {
    const randomIP_val = random_ip[domain_random] === 'eu' ? randomIP(185, 185) : randomIP();
    requestHeaders.push({ "name": "X-Forwarded-For", "value": randomIP_val });
  }

  if (!matchUrlDomain(allow_cookies, details.url)) {
    requestHeaders = requestHeaders.map(requestHeader => 
      requestHeader.name === 'Cookie' ? { ...requestHeader, value: '' } : requestHeader
    );
  }

  if (kiwi_browser) {
    const tabId = details.tabId;
    const isMainOrSubFrame = ['main_frame', 'sub_frame', 'xmlhttprequest'].includes(details.type);
    const queryTabs = () => ext_api.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs && tabs[0] && /^http/.test(tabs[0].url)) {
        const tab = tabs[0];
        if (isSiteEnabled(tab)) runOnTab(tab);
        runOnTab_once(tab);
        runOnTab_once_var(tab);
      }
    });

    if (tabId !== -1 && isMainOrSubFrame) {
      ext_api.tabs.get(tabId, tab => {
        if (!ext_api.runtime.lastError && tab && isSiteEnabled(tab)) runOnTab(tab);
        runOnTab_once(tab);
        runOnTab_once_var(tab);
      });
    } else if (isMainOrSubFrame) {
      queryTabs();
    }
  }

  return { requestHeaders };
}, {
  urls: ['*://*/*']
}, extraInfoSpec);
// extraInfoSpec is ['blocking', 'requestHeaders'] + possible 'extraHeaders'

async function check_sites_custom_ext() {
  try {
    const response = await fetch(sites_custom_ext_json);
    if (response.ok) {
      const json = await response.json();
      customSitesExt = Object.values(json).map(x => x.domain);
      if (json['###_remove_sites']?.cs_code) {
        customSitesExt_remove = json['###_remove_sites'].cs_code.split(/,\s?/);
      }
    }
  } catch (err) {
    console.error(err);
  }
}

var customSitesExt = [];
var customSitesExt_remove = [];
var sites_custom_ext_json = 'custom/sites_custom.json';

ext_api.tabs.onUpdated.addListener(function (tabId, info, tab) { updateBadge(tab); });
ext_api.tabs.onActivated.addListener(function (activeInfo) { if (activeInfo.tabId) ext_api.tabs.get(activeInfo.tabId, updateBadge); });

function updateBadge(activeTab) {
  if (ext_api.runtime.lastError || !activeTab || !activeTab.active)
    return;
  let badgeText = '';
  let color = 'red';
  let currentUrl = activeTab.url;
  if (currentUrl) {
    if (isSiteEnabled({url: currentUrl})) {
      badgeText = 'ON';
      color = 'red';
    } else if (matchUrlDomain(enabledSites, currentUrl)) {
      badgeText = 'ON-';
      color = 'orange';
    } else if (matchUrlDomain(disabledSites, currentUrl)) {
      badgeText = 'OFF';
      color = 'blue';
    } else if (matchUrlDomain(nofix_sites, currentUrl)) {
      badgeText = 'X';
      color = 'silver';
    }
    if (matchUrlDomain('webcache.googleusercontent.com', currentUrl))
      badgeText = '';
    if (ext_version_new > ext_version)
      badgeText = '^' + badgeText;
    let isDefaultSite = matchUrlDomain(defaultSites_domains, currentUrl);
    let isCustomSite = matchUrlDomain(customSites_domains, currentUrl);
    let isUpdatedSite = matchUrlDomain(updatedSites_domains_new, currentUrl);
    if (!isDefaultSite && (isCustomSite || isUpdatedSite)) {
      ext_api.permissions.contains({
        origins: ['*://*.' + (isCustomSite || isUpdatedSite) + '/*']
      }, function (result) {
        if (!result)
          badgeText = enabledSites.includes(isCustomSite || isUpdatedSite) ? 'C' : '';
        if (color && badgeText)
          ext_api.action.setBadgeBackgroundColor({color: color});
        ext_api.action.setBadgeText({text: badgeText});
      });
    } else {
      if (!badgeText && matchUrlDomain(customSitesExt, currentUrl))
        badgeText = '+C';
      if (color && badgeText)
        ext_api.action.setBadgeBackgroundColor({color: color});
      ext_api.action.setBadgeText({text: badgeText});
    }
  } else
      ext_api.action.setBadgeText({text: badgeText});
}

function setExtVersionNew(check_ext_version_new, check_ext_upd_version_new = '') {
  ext_api.management.getSelf(function (result) {
    var installType = result.installType;
    var ext_version_len = (installType === 'development') ? 7 : 5;
    ext_version_new = check_ext_version_new;
    if (ext_version_len === 5 && check_ext_upd_version_new && check_ext_upd_version_new < check_ext_version_new)
      ext_version_new = check_ext_upd_version_new;
    if (ext_version_new && ext_version_new.substring(0, ext_version_len) <= ext_version.substring(0, ext_version_len))
      ext_version_new = '1';
    ext_api.storage.local.set({
      ext_version_new: ext_version_new
    });
  });
}

let ext_version_new;
async function check_update() {
  const manifest_new = `${ext_path}manifest.json`;
  try {
    const response = await fetch(manifest_new);
    if (response.ok) {
      const json = await response.json();
      const json_ext_version_new = json['version'];
      if (manifestData.browser_specific_settings?.gecko?.update_url) {
        const json_upd_version_new = manifestData.browser_specific_settings.gecko.update_url;
        try {
          const response = await fetch(json_upd_version_new);
          if (response.ok) {
            const upd_json = await response.json();
            const ext_id = manifestData.browser_specific_settings.gecko.id;
            const json_ext_upd_version_new = upd_json.addons[ext_id].updates[0].version;
            setExtVersionNew(json_ext_version_new, json_ext_upd_version_new);
          }
        } catch (err) {
          setExtVersionNew(json_ext_version_new);
        }
      } else {
        setExtVersionNew(json_ext_version_new);
      }
    } else {
      setExtVersionNew('');
    }
  } catch (err) {
    setExtVersionNew('');
  }
}

function site_switch() {
  ext_api.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (tabs?.[0]?.url?.startsWith('http')) {
      const currentUrl = tabs[0].url;
      let isDefaultSite = matchUrlDomain(defaultSites_grouped_domains, currentUrl) || 
                         Object.keys(grouped_sites).find(key => grouped_sites[key].includes(matchUrlDomain(defaultSites_domains, currentUrl)));

      if (!isDefaultSite) {
        const sites_updated_domains_new = Object.values(updatedSites)
          .filter(x => x.domain && !defaultSites_domains.includes(x.domain))
          .map(x => x.domain);
        const isUpdatedSite = matchUrlDomain(sites_updated_domains_new, currentUrl) || 
                              Object.values(updatedSites)
                                .filter(x => x.group)
                                .flatMap(x => x.group.filter(y => !defaultSites_domains.includes(y)))
                                .find(group => matchUrlDomain([group], currentUrl));

        if (isUpdatedSite) isDefaultSite = isUpdatedSite;
      }

      const defaultSite_title = isDefaultSite ? Object.keys(defaultSites).find(key => defaultSites[key].domain === isDefaultSite) : '';
      const isCustomSite = matchUrlDomain(customSites_domains, currentUrl);
      const customSite_title = isCustomSite ? Object.keys(customSites).find(key => customSites[key].domain === isCustomSite || 
        (customSites[key].group && customSites[key].group.split(',').includes(isCustomSite))) : '';

      if (isCustomSite && customSite_title && customSites[customSite_title].domain !== isCustomSite) {
        isCustomSite = customSites[customSite_title].domain;
      }

      const isCustomFlexSite = matchUrlDomain(custom_flex_domains, currentUrl);
      const isCustomFlexGroupSite = isCustomFlexSite ? Object.keys(custom_flex).find(key => custom_flex[key].includes(isCustomFlexSite)) : '';
      const customFlexSite_title = isCustomFlexGroupSite ? Object.keys(defaultSites).find(key => defaultSites[key].domain === isCustomFlexGroupSite) : '';
      const site_title = defaultSite_title || customSite_title || customFlexSite_title;
      const domain = isDefaultSite || isCustomSite || isCustomFlexGroupSite;

      if (domain && site_title) {
        const added_site = enabledSites.includes(domain) ? [] : [site_title];
        const removed_site = enabledSites.includes(domain) ? [site_title] : [];

        ext_api.storage.local.get({ sites: {} }, function (items) {
          const sites = items.sites;
          added_site.forEach(key => sites[key] = domain);
          removed_site.forEach(key => {
            const siteKey = Object.keys(sites).find(sites_key => compareKey(sites_key, key));
            if (siteKey) delete sites[siteKey];
          });

          ext_api.storage.local.set({ sites }, function () {
            ext_api.tabs.reload({ bypassCache: true });
          });
        });
      }
    }
  });
}

function remove_cookies_fn(domainVar, exclusions = false) {
  ext_api.cookies.getAllCookieStores(cookieStores => {
    ext_api.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (!ext_api.runtime.lastError && tabs?.[0]?.url?.startsWith('http')) {
        const tabId = tabs[0].id;
        const storeId = cookieStores.find(store => store.tabIds.includes(tabId))?.id || '0';
        domainVar = domainVar === 'asia.nikkei.com' ? 'nikkei.com' : domainVar;

        const cookie_get_options = { domain: domainVar, ...(storeId !== 'null' && { storeId }) };
        ext_api.cookies.getAll(cookie_get_options, cookies => {
          cookies.forEach(cookie => {
            if (exclusions) {
              const rc_domain = cookie.domain.replace(/^(\.?www\.|\.)/, '');
              if ((rc_domain in remove_cookies_select_hold && remove_cookies_select_hold[rc_domain].includes(cookie.name)) ||
                  (rc_domain in remove_cookies_select_drop && !remove_cookies_select_drop[rc_domain].includes(cookie.name)) ||
                  cookie.name.match(/(consent|^optanon)/i)) {
                return; // ne pas supprimer le cookie spécifique
              }
            }
            cookie.domain = cookie.domain.replace(/^\./, '');
            const cookie_remove_options = {
              url: `${cookie.secure ? "https://" : "http://"}${cookie.domain}${cookie.path}`,
              name: cookie.name,
              ...(storeId !== 'null' && { storeId })
            };
            ext_api.cookies.remove(cookie_remove_options);
          });
        });
      }
    });
  });
}

function clear_cookies() {
  ext_api.tabs.query({
    active: true,
    currentWindow: true
  }, function (tabs) {
    if (tabs && tabs[0] && /^http/.test(tabs[0].url)) {
      ext_api.tabs.executeScript({
        file: 'options/clearCookies.js',
        runAt: 'document_start'
      }, function (res) {
        if (ext_api.runtime.lastError || res[0]) {
          return;
        }
      });
      ext_api.tabs.update(tabs[0].id, {
        url: tabs[0].url
      });
    }
  });
}

const chrome_scheme = 'light';
ext_api.runtime.onMessage.addListener((message, sender) => {
  switch (message.request) {
    case 'clear_cookies':
      clear_cookies();
      break;
    case 'clear_cookies_domain':
      if (message.data) {
        remove_cookies_fn(message.data.domain, true);
      }
      break;
    case 'custom_domain':
      if (message.data && message.data.domain) {
        const custom_domain = message.data.domain;
        const group = message.data.group;
        if (group) {
          const nofix_groups = ['###_beehiiv', '###_fi_alma_talent', '###_fi_kaleva', '###_ghost', '###_it_citynews', '###_nl_vmnmedia', '###_se_gota_media', '###_substack_custom', '###_uk_delinian', '###_usa_cherryroad'];
          if (!custom_flex_domains.includes(custom_domain)) {
            if (!nofix_groups.includes(group)) {
              custom_flex[group] = custom_flex[group] || [];
              custom_flex[group].push(custom_domain);
              custom_flex_domains.push(custom_domain);
              if (enabledSites.includes(group)) {
                if (!enabledSites.includes(custom_domain)) {
                  enabledSites.push(custom_domain);
                }
                let rules = Object.values(defaultSites).find(x => x.domain === group);
                if (rules) {
                  if (rules.exception) {
                    const exception_rule = rules.exception.find(x => custom_domain === x.domain || (typeof x.domain !== 'string' && x.domain.includes(custom_domain)));
                    if (exception_rule) {
                      rules = exception_rule;
                    }
                  }
                  if (group === '###_de_madsack' && !set_var_sites.includes(custom_domain)) {
                    set_var_sites.push(custom_domain);
                  }
                } else {
                  rules = Object.values(customSites).find(x => x.domain === group);
                }
                if (rules) {
                  customFlexAddRules(custom_domain, rules);
                }
              } else if (!disabledSites.includes(custom_domain)) {
                disabledSites.push(custom_domain);
              }
            } else {
              nofix_sites.push(custom_domain);
            }
          } else {
            custom_flex_not_domains.push(custom_domain);
          }
        }
      }
      break;
    case 'site_switch':
      site_switch();
      break;
    case 'check_sites_updated':
      check_sites_updated(sites_updated_json_online);
      break;
    case 'clear_sites_updated':
      clear_sites_updated();
      break;
    case 'check_update':
      check_update();
      break;
    case 'popup_show_toggle':
      ext_api.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && /^http/.test(tabs[0].url)) {
          const currentUrl = tabs[0].url;
          const isExcludedSite = matchUrlDomain(excludedSites, currentUrl);
          if (!isExcludedSite) {
            const domain = [defaultSites_domains, customSites_domains, updatedSites_domains_new, custom_flex_domains].some(sites => matchUrlDomain(sites, currentUrl));
            if (domain) {
              ext_api.runtime.sendMessage({
                msg: "popup_show_toggle",
                data: {
                  domain: domain,
                  enabled: enabledSites.includes(domain)
                }
              });
            }
          }
        }
      });
      break;
    case 'refreshCurrentTab':
      ext_api.tabs.reload(sender.tab.id, { bypassCache: true });
      break;
    case 'getExtSrc':
      if (message.data) {
        message.data.html = '';
        const sendArticleSrc = (message) => {
          ext_api.tabs.sendMessage(sender.tab.id, {
            msg: "showExtSrc",
            data: message.data
          });
        };
    function getArticleSrc(message) {
      let url_src = message.data.url_src || message.data.url;
      fetch(url_src)
      .then(response => {
        if (response.ok) {
          response.text().then(html => {
            let recursive;
            if (message.data.url.startsWith('https://archive.')) {
              if (url_src.includes('/https')) {
                if (html.includes('<div class="TEXT-BLOCK"')) {
                  message.data.url_src = html.split('<div class="TEXT-BLOCK"')[1].split('</div>')[0].split('href="')[1].split('"')[0];
                  getArticleSrc(message);
                  recursive = true;
                } else
                  html = '';
              }
            }
            if (!recursive) {
              if (html) {
                if (message.data.base64) {
                  html = decode_utf8(atob(html));
                  message.data.selector_source = 'body';
                }
                if (typeof DOMParser === 'function') {
                  let parser = new DOMParser();
                  let doc = parser.parseFromString(html, 'text/html');
                  let article_new = doc.querySelector(message.data.selector_source);
                  if (article_new)
                    html = article_new.outerHTML;
                  else
                    html = '';
                }
              }
              message.data.html = html;
              sendArticleSrc(message);
            }
          });
        } else
          sendArticleSrc(message);
      }).catch(function (err) {
        sendArticleSrc(message);
      });
    }
    getArticleSrc(message);
  }
  if (message.scheme && (![chrome_scheme, 'undefined'].includes(message.scheme) || focus_changed)) {
    let icon_path = {path: {'128': 'bypass.png'}};
    if (message.scheme === 'dark')
      icon_path = {path: {'128': 'bypass-dark.png'}};
    ext_api.action.setIcon(icon_path);
    chrome_scheme = message.scheme;
    focus_changed = false;
  }
});
// Afficher l'onglet d'opt-in lors de l'installation
ext_api.storage.local.get(["optInShown", "customShown"]).then(result => {
  if (!result.optInShown || !result.customShown) {
    ext_api.tabs.create({ url: "options/optin/opt-in.html" });
    ext_api.storage.local.set({ "optInShown": true, "customShown": true });
  }
});

function filterObject(obj, filterFn, mapFn = function (val, key) {
  return [key, val];
}) {
  return Object.fromEntries(Object.entries(obj).
    filter(([key, val]) => filterFn(val, key)).map(([key, val]) => mapFn(val, key)));
}

function compareKey(firstStr, secondStr) {
  return firstStr.toLowerCase().replace(/\s\(.*\)/, '') === secondStr.toLowerCase().replace(/\s\(.*\)/, '');
}

function isSiteEnabled(details) {
  var enabledSite = matchUrlDomain(enabledSites, details.url);
  if (!ext_name.startsWith('Bypass Paywalls Clean') || !(self_hosted || /0$/.test(ext_version)))
    enabledSite = '';
  if (enabledSite in restrictions) {
    return restrictions[enabledSite].test(details.url);
  }
  return !!enabledSite;
}

function matchDomain(domains, hostname = '') {
  var matched_domain = false;
  if (typeof domains === 'string')
    domains = [domains];
  domains.some(domain => (hostname === domain || hostname.endsWith('.' + domain)) && (matched_domain = domain));
  return matched_domain;
}

function urlHost(url) {
  if (/^http/.test(url)) {
    try {
      return new URL(url).hostname;
    } catch (e) {
      console.log(`url not valid: ${url} error: ${e}`);
    }
  }
  return url;
}

function matchUrlDomain(domains, url) {
  return matchDomain(domains, urlHost(url));
}

function prepHostname(hostname) {
  return hostname.replace(/^(www|m|account|amp(\d)?|edition|eu|mobil|wap)\./, '');
}

function getParameterByName(name, url) {
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
  results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

function stripUrl(url) {
  return url.split(/[\?#]/)[0];
}

function decode_utf8(str) {
  return decodeURIComponent(escape(str));
}

function randomInt(max) {
  return Math.floor(Math.random() * Math.floor(max));
}

function randomIP(range_low = 0, range_high = 223) {
  let rndmIP = [];
  for (let n = 0; n < 4; n++) {
    if (n === 0)
      rndmIP.push(range_low + randomInt(range_high - range_low + 1));
    else
      rndmIP.push(randomInt(255) + 1);
  }
  return rndmIP.join('.');
}

// Refresh the current tab (http)
function refreshCurrentTab() {
  ext_api.tabs.query({
    active: true,
    currentWindow: true
  }, function (tabs) {
    if (tabs && tabs[0] && /^http/.test(tabs[0].url)) {
      if (ext_api.runtime.lastError)
        return;
      ext_api.tabs.update(tabs[0].id, {
        url: tabs[0].url
      });
    }
  });
}
