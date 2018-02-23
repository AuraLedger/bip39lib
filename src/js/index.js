(function() {

  window.bip39js = {
    getNetworks: getNetworks,
    setNetIndex: setNetIndex,
    generateRandomPhrase: generateRandomPhrase,
    calcBip32RootKeyFromSeed: calcBip32RootKeyFromSeed,
    calcBip32ExtendedKey: calcBip32ExtendedKey,
    setErrHandler: setErrHandler,
    getBip44DerivationPath: getBip44DerivationPath,
    getBip44Info: getBip44Info,
    deriveAddress: deriveAddress,
    setMnemonicLanguage: setMnemonicLanguage,
  };

  // mnemonics is populated as required by getLanguage
  var mnemonics = { "english": new Mnemonic("english") };
  var mnemonic = mnemonics["english"];
  var seed = null;
  var bip32RootKey = null;
  var bip32ExtendedKey = null;
  var network = bitcoinjs.bitcoin.networks.bitcoin;
  var hdCoin = 0;
  var netIndex = 0;

  function setNetIndex(ind) {
    netIndex = ind;
  }

  function getNetworks() {
    return networks; 
  }

  var litecoinUseLtub = true;

  // Private methods
  function generateRandomPhrase(numWords) {
    if (!hasStrongRandom()) {
      var errorText = "This browser does not support strong randomness";
      showValidationError(errorText);
      return;
    }
    // get the amount of entropy to use
    numWords = numWords || 15;
    var strength = numWords / 3 * 32;
    var buffer = new Uint8Array(strength / 8);
    // create secure entropy
    var data = crypto.getRandomValues(buffer);
    // create the words
    var words = mnemonic.toMnemonic(data);
    return words;
  }

  function calcBip32RootKeyFromSeed(phrase, passphrase) {
    seed = mnemonic.toSeed(phrase, passphrase);
    bip32RootKey = bitcoinjs.bitcoin.HDNode.fromSeedHex(seed, network);
  }

  function calcBip32RootKeyFromBase58(rootKeyBase58) {
    bip32RootKey = bitcoinjs.bitcoin.HDNode.fromBase58(rootKeyBase58, network);
  }

  function calcBip32ExtendedKey(path) {
    // Check there's a root key to derive from
    if (!bip32RootKey) {
      return bip32RootKey;
    }
    var extendedKey = bip32RootKey;
    // Derive the key from the path
    var pathBits = path.split("/");
    for (var i=0; i<pathBits.length; i++) {
      var bit = pathBits[i];
      var index = parseInt(bit);
      if (isNaN(index)) {
        continue;
      }
      var hardened = bit[bit.length-1] == "'";
      var isPriv = !(extendedKey.isNeutered());
      var invalidDerivationPath = hardened && !isPriv;
      if (invalidDerivationPath) {
        extendedKey = null;
      }
      else if (hardened) {
        extendedKey = extendedKey.deriveHardened(index);
      }
      else {
        extendedKey = extendedKey.derive(index);
      }
    }
    return extendedKey
  }


  var errHandler;

  function setErrHandler(handler) {
    errHandler = handler;
  }

  function showValidationError(errorText) {
    console.err(errorText);
    if(errHandler)
      errHandler(errorText);
  }

  function findPhraseErrors(phrase) {
    // Preprocess the words
    phrase = mnemonic.normalizeString(phrase);
    var words = phraseToWordArray(phrase);
    // Detect blank phrase
    if (words.length == 0) {
      return "Blank mnemonic";
    }
    // Check each word
    for (var i=0; i<words.length; i++) {
      var word = words[i];
      var language = getLanguage();
      if (WORDLISTS[language].indexOf(word) == -1) {
        console.log("Finding closest match to " + word);
        var nearestWord = findNearestWord(word);
        return word + " not in wordlist, did you mean " + nearestWord + "?";
      }
    }
    // Check the words are valid
    var properPhrase = wordArrayToPhrase(words);
    var isValid = mnemonic.check(properPhrase);
    if (!isValid) {
      return "Invalid mnemonic";
    }
    return false;
  }

  function validateRootKey(rootKeyBase58) {
    try {
      bitcoinjs.bitcoin.HDNode.fromBase58(rootKeyBase58, network);
    }
    catch (e) {
      return "Invalid root key";
    }
    return "";
  }

  function getBip44DerivationPath(purpose, coin, account, change) {
    purpose = parseIntNoNaN(purpose, 44);
    coin = parseIntNoNaN(coin, 0);
    account = parseIntNoNaN(account, 0);
    change = parseIntNoNaN(change, 0);
    var path = "m/";
    path += purpose + "'/";
    path += coin + "'/";
    path += account + "'/";
    path += change;
    return path;
  }

  function findDerivationPathErrors(path) {
    // TODO is not perfect but is better than nothing
    // Inspired by
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    // and
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#extended-keys
    var maxDepth = 255; // TODO verify this!!
    var maxIndexValue = Math.pow(2, 31); // TODO verify this!!
    if (path[0] != "m") {
      return "First character must be 'm'";
    }
    if (path.length > 1) {
      if (path[1] != "/") {
        return "Separator must be '/'";
      }
      var indexes = path.split("/");
      if (indexes.length > maxDepth) {
        return "Derivation depth is " + indexes.length + ", must be less than " + maxDepth;
      }
      for (var depth = 1; depth<indexes.length; depth++) {
        var index = indexes[depth];
        var invalidChars = index.replace(/^[0-9]+'?$/g, "")
        if (invalidChars.length > 0) {
          return "Invalid characters " + invalidChars + " found at depth " + depth;
        }
        var indexValue = parseInt(index.replace("'", ""));
        if (isNaN(depth)) {
          return "Invalid number at depth " + depth;
        }
        if (indexValue > maxIndexValue) {
          return "Value of " + indexValue + " at depth " + depth + " must be less than " + maxIndexValue;
        }
      }
    }
    // Check root key exists or else derivation path is useless!
    if (!bip32RootKey) {
      return "No root key";
    }
    // Check no hardened derivation path when using xpub keys
    var hardenedPath = path.indexOf("'") > -1;
    var hardenedAddresses = false;
    var hardened = hardenedPath || hardenedAddresses;
    var isXpubkey = bip32RootKey.isNeutered();
    if (hardened && isXpubkey) {
      return "Hardened derivation path is invalid with xpub key";
    }
    return false;
  }

  function getBip44Info(path) {
    // Calculate the account extended keys
    var accountExtendedKey = calcBip32ExtendedKey(path);
    var accountXprv = accountExtendedKey.toBase58();
    var accountXpub = accountExtendedKey.neutered().toBase58();

    return { 
      accountExtendedKey: accountExtendedKey, 
      accountXprv: accountXprv, 
      accountXpub : accountXpub 
    };
  }

  function deriveAddress(index) {

    var isLast = true;
    var useHardenedAddresses = true;
    var useBip38 = false;
    var bip38password = "";
    var isSegwit = false;
    var segwitAvailable = networkHasSegwit();
    var isP2wpkh = false;
    var isP2wpkhInP2sh = false;

    // derive HDkey for this row of the table
    var key = "NA";
    if (useHardenedAddresses) {
      key = bip32ExtendedKey.deriveHardened(index);
    }
    else {
      key = bip32ExtendedKey.derive(index);
    }
    // bip38 requires uncompressed keys
    // see https://github.com/iancoleman/bip39/issues/140#issuecomment-352164035
    var keyPair = key.keyPair;
    var useUncompressed = useBip38;
    if (useUncompressed) {
      keyPair = new bitcoinjs.bitcoin.ECPair(keyPair.d, null, { compressed: false });
    }
    // get address
    var address = keyPair.getAddress().toString();
    // get privkey
    var hasPrivkey = !key.isNeutered();
    var privkey = "NA";
    if (hasPrivkey) {
      privkey = keyPair.toWIF(network);
      // BIP38 encode private key if required
      if (useBip38) {
        privkey = bitcoinjsBip38.encrypt(keyPair.d.toBuffer(), false, bip38password, function(p) {
          console.log("Progressed " + p.percent.toFixed(1) + "% for index " + index);
        });
      }
    }
    // get pubkey
    var pubkey = keyPair.getPublicKeyBuffer().toString('hex');
    var indexText = getDerivationPath() + "/" + index;
    if (useHardenedAddresses) {
      indexText = indexText + "'";
    }
    // Ethereum values are different
    if (networks[netIndex].ether) {
      var privKeyBuffer = keyPair.d.toBuffer(32);
      privkey = privKeyBuffer.toString('hex');
      var addressBuffer = ethUtil.privateToAddress(privKeyBuffer);
      var hexAddress = addressBuffer.toString('hex');
      var checksumAddress = ethUtil.toChecksumAddress(hexAddress);
      address = ethUtil.addHexPrefix(checksumAddress);
      privkey = ethUtil.addHexPrefix(privkey);
      pubkey = ethUtil.addHexPrefix(pubkey);
    }
    // Ripple values are different
    if (networks[netIndex].name == "XRP - Ripple") {
      privkey = convertRipplePriv(privkey);
      address = convertRippleAdrr(address);
    }
    // Segwit addresses are different
    if (isSegwit) {
      if (!segwitAvailable) {
        return;
      }
      if (isP2wpkh) {
        var keyhash = bitcoinjs.bitcoin.crypto.hash160(key.getPublicKeyBuffer());
        var scriptpubkey = bitcoinjs.bitcoin.script.witnessPubKeyHash.output.encode(keyhash);
        address = bitcoinjs.bitcoin.address.fromOutputScript(scriptpubkey, network)
      }
      else if (isP2wpkhInP2sh) {
        var keyhash = bitcoinjs.bitcoin.crypto.hash160(key.getPublicKeyBuffer());
        var scriptsig = bitcoinjs.bitcoin.script.witnessPubKeyHash.output.encode(keyhash);
        var addressbytes = bitcoinjs.bitcoin.crypto.hash160(scriptsig);
        var scriptpubkey = bitcoinjs.bitcoin.script.scriptHash.output.encode(addressbytes);
        address = bitcoinjs.bitcoin.address.fromOutputScript(scriptpubkey, network)
      }
    }
    return {
      address: address,
      privkey: privkey,
      pubkey: pubkey
    }
  }

  function hasStrongRandom() {
    return 'crypto' in window && window['crypto'] !== null;
  }

  function parseIntNoNaN(val, defaultVal) {
    var v = parseInt(val);
    if (isNaN(v)) {
      return defaultVal;
    }
    return v;
  }

  function findNearestWord(word) {
    var language = getLanguage();
    var words = WORDLISTS[language];
    var minDistance = 99;
    var closestWord = words[0];
    for (var i=0; i<words.length; i++) {
      var comparedTo = words[i];
      if (comparedTo.indexOf(word) == 0) {
        return comparedTo;
      }
      var distance = Levenshtein.get(word, comparedTo);
      if (distance < minDistance) {
        closestWord = comparedTo;
        minDistance = distance;
      }
    }
    return closestWord;
  }

  function getLanguage() {
    var defaultLanguage = "english";
    // Try to get from existing phrase
    var language = getLanguageFromPhrase();
    // Try to get from url if not from phrase
    if (language.length == 0) {
      language = getLanguageFromUrl();
    }
    // Default to English if no other option
    if (language.length == 0) {
      language = defaultLanguage;
    }
    return language;
  }

  function getLanguageFromPhrase(phrase) {
    // Check if how many words from existing phrase match a language.
    var language = "";
    if (phrase.length > 0) {
      var words = phraseToWordArray(phrase);
      var languageMatches = {};
      for (l in WORDLISTS) {
        // Track how many words match in this language
        languageMatches[l] = 0;
        for (var i=0; i<words.length; i++) {
          var wordInLanguage = WORDLISTS[l].indexOf(words[i]) > -1;
          if (wordInLanguage) {
            languageMatches[l]++;
          }
        }
        // Find languages with most word matches.
        // This is made difficult due to commonalities between Chinese
        // simplified vs traditional.
        var mostMatches = 0;
        var mostMatchedLanguages = [];
        for (var l in languageMatches) {
          var numMatches = languageMatches[l];
          if (numMatches > mostMatches) {
            mostMatches = numMatches;
            mostMatchedLanguages = [l];
          }
          else if (numMatches == mostMatches) {
            mostMatchedLanguages.push(l);
          }
        }
      }
      if (mostMatchedLanguages.length > 0) {
        // Use first language and warn if multiple detected
        language = mostMatchedLanguages[0];
        if (mostMatchedLanguages.length > 1) {
          console.warn("Multiple possible languages");
          console.warn(mostMatchedLanguages);
        }
      }
    }
    return language;
  }

  function getLanguageFromUrl() {
    for (var language in WORDLISTS) {
      if (window.location.hash.indexOf(language) > -1) {
        return language;
      }
    }
    return "";
  }

  function setMnemonicLanguage() {
    var language = getLanguage();
    // Load the bip39 mnemonic generator for this language if required
    if (!(language in mnemonics)) {
      mnemonics[language] = new Mnemonic(language);
    }
    mnemonic = mnemonics[language];
  }

  function convertPhraseToNewLanguage(oldPhrase) {
    var oldLanguage = getLanguageFromPhrase();
    var newLanguage = getLanguageFromUrl();
    var oldWords = phraseToWordArray(oldPhrase);
    var newWords = [];
    for (var i=0; i<oldWords.length; i++) {
      var oldWord = oldWords[i];
      var index = WORDLISTS[oldLanguage].indexOf(oldWord);
      var newWord = WORDLISTS[newLanguage][index];
      newWords.push(newWord);
    }
    newPhrase = wordArrayToPhrase(newWords);
    return newPhrase;
  }

  // TODO look at jsbip39 - mnemonic.splitWords
  function phraseToWordArray(phrase) {
    var words = phrase.split(/\s/g);
    var noBlanks = [];
    for (var i=0; i<words.length; i++) {
      var word = words[i];
      if (word.length > 0) {
        noBlanks.push(word);
      }
    }
    return noBlanks;
  }

  // TODO look at jsbip39 - mnemonic.joinWords
  function wordArrayToPhrase(words) {
    var phrase = words.join(" ");
    var language = getLanguageFromPhrase(phrase);
    if (language == "japanese") {
      phrase = words.join("\u3000");
    }
    return phrase;
  }


  function setHdCoin(coinValue) {
    hdCoin = coinValue;
  }
  function adjustNetworkForSegwit() {
    // If segwit is selected the xpub/xprv prefixes need to be adjusted
    // to avoid accidentally importing BIP49 xpub to BIP44 watch only
    // wallet.
    // See https://github.com/iancoleman/bip39/issues/125
    var segwitNetworks = null;
    // if a segwit network is alread selected, need to use base network to
    // look up new parameters
    if ("baseNetwork" in network) {
      network = bitcoinjs.bitcoin.networks[network.baseNetwork];
    }
    // choose the right segwit params
    if (p2wpkhSelected() && "p2wpkh" in network) {
      network = network.p2wpkh;
    }
    else if (p2wpkhInP2shSelected() && "p2wpkhInP2sh" in network) {
      network = network.p2wpkhInP2sh;
    }
  }

  function uint8ArrayToHex(a) {
    var s = ""
    for (var i=0; i<a.length; i++) {
      var h = a[i].toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      s = s + h;
    }
    return s;
  }

  function showWordIndexes(phrase) {
    var words = phraseToWordArray(phrase);
    var wordIndexes = [];
    var language = getLanguage();
    for (var i=0; i<words.length; i++) {
      var word = words[i];
      var wordIndex = WORDLISTS[language].indexOf(word);
      wordIndexes.push(wordIndex);
    }
    var wordIndexesStr = wordIndexes.join(", ");
    return wordIndexesStr;
  }


  var networks = [
    {
      name: "AXE - Axe",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.axe;
        setHdCoin(0);
      },
    },
    {
      name: "BCH - Bitcoin Cash",
      segwitAvailable: false,
      onSelect: function() {
        setBitcoinCashNetworkValues();
        setHdCoin(145);
      },
    },
    {
      name: "BTC - Bitcoin",
      segwitAvailable: true,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(0);
      },
    },
    {
      name: "BTC - Bitcoin Testnet",
      segwitAvailable: true,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.testnet;
        setHdCoin(1);
      },
    },
    {
      name: "BTG - Bitcoin Gold",
      segwitAvailable: true,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bgold;
        setHdCoin(0);
      },
    },
    {
      name: "CLAM - Clams",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.clam;
        setHdCoin(23);
      },
    },
    {
      name: "CRW - Crown",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.crown;
        setHdCoin(72);
      },
    },
    {
      name: "DASH - Dash",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.dash;
        setHdCoin(5);
      },
    },
    {
      name: "DASH - Dash Testnet",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.dashtn;
        setHdCoin(1);
      },
    },
    {
      name: "DOGE - Dogecoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.dogecoin;
        setHdCoin(3);
      },
    },
    {
      name: "ARA - Aura",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(312);
      },
    },
    {
      name: "ETC - Ethereum Classic",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(61);
      },
    },
    {
      name: "ETH - Ethereum",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(60);
      },
    },
    {
      name: "EXP - Expanse",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(40);
      },
    },
    {
      name: "UBQ - Ubiq",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(108);
      },
    },
    {
      name: "ELLA - Ellaism",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(163);
      },
    },
    {
      name: "PIRL - Pirl",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(164);
      },
    },
    {
      name: "MUSIC - Musicoin",
      segwitAvailable: false,
      ether: true,  
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(184);
      },
    },
    {
      name: "FJC - Fujicoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.fujicoin;
        setHdCoin(75);
      },
    },
    {
      name: "GAME - GameCredits",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.game;
        setHdCoin(101);
      },
    },
    {
      name: "JBS - Jumbucks",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.jumbucks;
        setHdCoin(26);
      },
    },
    {
      name: "KMD - Komodo",
      bip49available: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.komodo;
        setHdCoin(141);
      },
    },
    {
      name: "LTC - Litecoin",
      segwitAvailable: true,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.litecoin;
        setHdCoin(2);
      },
    },
    {
      name: "MAZA - Maza",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.maza;
        setHdCoin(13);
      },
    },
    {
      name: "MONA - Monacoin",
      segwitAvailable: true,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.monacoin,
          setHdCoin(22);
      },
    },
    {
      name: "NMC - Namecoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.namecoin;
        setHdCoin(7);
      },
    },
    {
      name: "ONX - Onixcoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.onixcoin;
        setHdCoin(174);
      },
    },
    {
      name: "PIVX - PIVX",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.pivx;
        setHdCoin(119);
      },
    },
    {
      name: "PIVX - PIVX Testnet",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.pivxtestnet;
        setHdCoin(1);
      },
    },
    {
      name: "PPC - Peercoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.peercoin;
        setHdCoin(6);
      },
    },
    {
      name: "SDC - ShadowCash",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.shadow;
        setHdCoin(35);
      },
    },
    {
      name: "SDC - ShadowCash Testnet",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.shadowtn;
        setHdCoin(1);
      },
    },
    {
      name: "SLM - Slimcoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.slimcoin;
        setHdCoin(63);
      },
    },
    {
      name: "SLM - Slimcoin Testnet",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.slimcointn;
        setHdCoin(111);
      },
    },
    {
      name: "USNBT - NuBits",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.nubits;
        setHdCoin(12);
      },
    },
    {
      name: "VIA - Viacoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.viacoin;
        setHdCoin(14);
      },
    },
    {
      name: "VIA - Viacoin Testnet",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.viacointestnet;
        setHdCoin(1);
      },
    },
    {
      name: "XMY - Myriadcoin",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.myriadcoin;
        setHdCoin(90);
      },
    },
    {
      name: "XRP - Ripple",
      segwitAvailable: false,
      onSelect: function() {
        network = bitcoinjs.bitcoin.networks.bitcoin;
        setHdCoin(144);
      },
    }
  ];

  var clients = [
    {
      name: "Bitcoin Core",
      onSelect: function() {
        DOM.hardenedAddresses.prop('checked', true);
      },
    },
    {
      name: "blockchain.info",
      onSelect: function() {
        DOM.hardenedAddresses.prop('checked', false);
      },
    },
    {
      name: "MultiBit HD",
      onSelect: function() {
        DOM.hardenedAddresses.prop('checked', false);
      },
    }
  ];

})();
