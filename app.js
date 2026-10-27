/* Pass Forge — every random choice uses crypto.getRandomValues with rejection sampling. Nothing is stored except option choices. */
(function () {
  "use strict";
  var $ = S3.$, $$ = S3.$$;
  var SETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!#$%&*+-=?@^_~()[]{}<>.,:;/|"
  };
  var LOOKALIKE = "Il1|O0o";
  var WORDS = Array.from(new Set(window.PF_WORDS || []));
  var GUESS_RATE = 1e11; // offline attack, fast hash, large GPU rig

  // ---------- randomness ----------
  function cryptoU32() { var b = new Uint32Array(1); crypto.getRandomValues(b); return b[0]; }
  // Uniform integer in [0, n): reject the top sliver of the 32-bit range that would bias the modulo.
  function randIntFrom(n, next) {
    if (!(n >= 1 && n <= 4294967296 && n === Math.floor(n))) throw new Error("bad range " + n);
    var limit = Math.floor(4294967296 / n) * n, x;
    do { x = next(); } while (x >= limit);
    return x % n;
  }
  function randInt(n) { return randIntFrom(n, cryptoU32); }

  // ---------- big-number helpers for exact entropy ----------
  function log2Big(x) {
    if (x <= 0n) return -Infinity;
    var bits = x.toString(2).length;
    if (bits <= 53) return Math.log2(Number(x));
    return Math.log2(Number(x >> BigInt(bits - 53))) + (bits - 53);
  }
  // Number of length-L strings over the pool that contain at least one char from every required set (inclusion-exclusion).
  function countValid(poolSize, setSizes, L) {
    var k = setSizes.length, total = 0n;
    for (var mask = 0; mask < (1 << k); mask++) {
      var removed = 0, bitsOn = 0;
      for (var i = 0; i < k; i++) if (mask & (1 << i)) { removed += setSizes[i]; bitsOn++; }
      var term = BigInt(poolSize - removed) ** BigInt(L);
      total += bitsOn % 2 ? -term : term;
    }
    return total;
  }

  // ---------- generators ----------
  function buildSets(o) {
    var ban = (o.lookalike ? LOOKALIKE : "") + (o.exclude || "");
    var sets = [];
    ["lower", "upper", "digits", "symbols"].forEach(function (k) {
      if (!o[k]) return;
      var chars = Array.from(SETS[k]).filter(function (c) { return ban.indexOf(c) < 0; }).join("");
      if (chars) sets.push({ name: k, chars: chars });
    });
    return sets;
  }
  function passwordPlan(o) {
    var sets = buildSets(o), pool = sets.map(function (s) { return s.chars; }).join("");
    var req = o.require && sets.length > 1 && o.length >= sets.length;
    var bits = !pool.length ? 0 : req
      ? log2Big(countValid(pool.length, sets.map(function (s) { return s.chars.length; }), o.length))
      : o.length * Math.log2(pool.length);
    return { sets: sets, pool: Array.from(pool), require: req, bits: bits };
  }
  function makePassword(o, plan) {
    plan = plan || passwordPlan(o);
    if (!plan.pool.length) return "";
    for (var tries = 0; tries < 100000; tries++) {
      var out = "";
      for (var i = 0; i < o.length; i++) out += plan.pool[randInt(plan.pool.length)];
      if (!plan.require || plan.sets.every(function (s) { return Array.from(out).some(function (c) { return s.chars.indexOf(c) >= 0; }); })) return out;
    }
    throw new Error("Could not satisfy the rules");
  }
  function phraseBits(o) {
    var b = o.words * Math.log2(WORDS.length);
    if (o.addnum) b += Math.log2(100) + Math.log2(o.words);
    return b;
  }
  function makePhrase(o) {
    var w = [];
    for (var i = 0; i < o.words; i++) w.push(WORDS[randInt(WORDS.length)]);
    if (o.cap || o.sep === "") w = w.map(function (x) { return x.charAt(0).toUpperCase() + x.slice(1); });
    if (o.addnum) { var at = randInt(w.length); w[at] += randInt(100); }
    return w.join(o.sep);
  }

  // ---------- UI ----------
  var DEFAULTS = { mode: "password", length: 20, lower: true, upper: true, digits: true, symbols: true, lookalike: true, require: true, exclude: "", words: 6, sep: "-", cap: false, addnum: false, count: 10 };
  var saved = S3.store("pf.opts") || {};
  var o = Object.assign({}, DEFAULTS, saved);
  var listText = "";

  function readUI() {
    o.length = clamp(+$("#lenn").value || 20, 8, 128);
    ["lower", "upper", "digits", "symbols", "lookalike", "require", "cap", "addnum"].forEach(function (k) { o[k] = $("#" + k).checked; });
    o.exclude = $("#exclude").value;
    o.words = +$("#words").value;
    o.sep = $("#sep").value;
    o.count = clamp(+$("#count").value || 10, 1, 1000);
    S3.store("pf.opts", o);
  }
  function writeUI() {
    $("#len").value = $("#lenn").value = o.length;
    ["lower", "upper", "digits", "symbols", "lookalike", "require", "cap", "addnum"].forEach(function (k) { $("#" + k).checked = !!o[k]; });
    $("#exclude").value = o.exclude; $("#words").value = o.words; $("#wordsv").textContent = o.words;
    $("#sep").value = o.sep; $("#count").value = o.count;
    $$("#mode button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.v === o.mode)); });
    $("#opt-password").hidden = o.mode !== "password"; $("#opt-phrase").hidden = o.mode !== "phrase";
  }
  function clamp(v, a, b) { return Math.max(a, Math.min(b, Math.round(v))); }

  function fmtTime(sec) {
    if (sec < 1) return "less than a second";
    var units = [["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    if (sec >= 31557600 * 1e6) {
      var y = sec / 31557600, big = [["quintillion", 1e18], ["quadrillion", 1e15], ["trillion", 1e12], ["billion", 1e9], ["million", 1e6]];
      if (y >= 1e21) return "about 10^" + Math.floor(Math.log10(y)) + " years";
      for (var j = 0; j < big.length; j++) if (y >= big[j][1]) return (y / big[j][1]).toFixed(1).replace(/\.0$/, "") + " " + big[j][0] + " years";
    }
    for (var i = 0; i < units.length; i++) if (sec >= units[i][1]) {
      var n = Math.floor(sec / units[i][1]);
      return n.toLocaleString() + " " + units[i][0] + (n === 1 ? "" : "s");
    }
    return "";
  }
  function grade(bits) {
    if (bits < 40) return ["Weak", "bad", 0.18];
    if (bits < 60) return ["Fair", "warn", 0.42];
    if (bits < 80) return ["Strong", "ok", 0.7];
    if (bits < 128) return ["Very strong", "ok", 0.88];
    return ["Overkill (excellent)", "ok", 1];
  }

  function current() {
    if (o.mode === "phrase") return { bits: phraseBits(o), gen: function () { return makePhrase(o); } };
    var plan = passwordPlan(o);
    return { bits: plan.bits, plan: plan, gen: function () { return makePassword(o, plan); } };
  }
  function info(cur) {
    if (o.mode === "password") {
      var p = cur.plan;
      $("#poolinfo").textContent = p.pool.length
        ? p.pool.length + " possible characters" + (o.require && !p.require && p.sets.length > 1 && o.length < p.sets.length ? " · too short to require every set" : "")
        : "Pick at least one character set.";
    } else {
      $("#listinfo").textContent = WORDS.length.toLocaleString() + " built-in words · " + Math.log2(WORDS.length).toFixed(2) + " bits per word" +
        (o.sep === "" ? " · without a separator, words run together (still capitalized so you can read them)" : "");
    }
  }
  function generate() {
    readUI();
    var cur = current(), pw = cur.gen();
    info(cur);
    var pass = $("#pass");
    pass.textContent = pw || "—";
    pass.classList.toggle("long", pw.length > 40);
    var g = grade(cur.bits);
    $("#bits").textContent = (pw ? cur.bits.toFixed(1) : "0") + " bits of entropy";
    $("#bits").className = "chip " + (pw ? "accent" : "");
    $("#label").textContent = pw ? g[0] : "—"; $("#label").className = "chip " + (pw ? g[1] : "");
    var m = $("#meter"); m.style.width = (pw ? g[2] * 100 : 0) + "%"; m.className = "pf-" + g[1];
    $("#crack").textContent = pw ? "≈ " + fmtTime(Math.pow(2, cur.bits - 1) / GUESS_RATE) + " to crack at 100 billion guesses/s" : "";
    return pw;
  }

  function bulk() {
    readUI();
    var cur = current(), lines = [];
    if (o.mode === "password" && !cur.plan.pool.length) { S3.toast("Pick at least one character set", "error"); return; }
    for (var i = 0; i < o.count; i++) lines.push(cur.gen());
    listText = lines.join("\n");
    $("#list").textContent = listText;
    S3.done();
  }

  $$("#mode button").forEach(function (b) {
    b.addEventListener("click", function () { o.mode = b.dataset.v; writeUI(); generate(); });
  });
  $("#len").addEventListener("input", function () { $("#lenn").value = this.value; generate(); });
  $("#lenn").addEventListener("change", function () { var v = clamp(+this.value || 20, 8, 128); this.value = $("#len").value = v; generate(); });
  $("#words").addEventListener("input", function () { $("#wordsv").textContent = this.value; generate(); });
  $$("#opt-password input[type=checkbox], #opt-phrase input[type=checkbox], #sep").forEach(function (el) { el.addEventListener("change", generate); });
  $("#exclude").addEventListener("input", S3.debounce(generate, 200));
  $("#count").addEventListener("change", function () { readUI(); });
  $("#regen").addEventListener("click", generate);
  function copyPass() { var t = $("#pass").textContent; if (t && t !== "—") { S3.copy(t, "Password copied"); S3.done(); } }
  $("#copy").addEventListener("click", copyPass);
  $("#pass").addEventListener("click", copyPass);
  $("#pass").addEventListener("keydown", function (e) { if (e.key === "Enter") copyPass(); });
  $("#bulk").addEventListener("click", bulk);
  $("#bulkcopy").addEventListener("click", function () { if (listText) S3.copy(listText, "List copied"); else S3.toast("Generate a list first", "error"); });
  $("#bulksave").addEventListener("click", function () { if (listText) { S3.download(listText + "\n", "passwords.txt", "text/plain"); S3.done(); } else S3.toast("Generate a list first", "error"); });
  document.addEventListener("keydown", function (e) {
    if ((e.key === "r" || e.key === "R") && !e.ctrlKey && !e.metaKey && !e.altKey && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); generate(); }
  });

  writeUI();
  generate();

  window.S3_DEMO = function () { o.mode = "password"; writeUI(); generate(); $("#count").value = 6; bulk(); };

  window.S3_SELFTEST = function () {
    var ok = true, fail = function (why) { ok = false; console.error("selftest: " + why); };
    // Rejection sampling: for n=3 the limit is 4294967295, so 4294967295 must be rejected and 5 accepted (5 % 3 = 2).
    var seq = [4294967295, 5], i = 0;
    if (randIntFrom(3, function () { return seq[i++]; }) !== 2 || i !== 2) fail("rejection sampling");
    var seq2 = [4294967295], j = 0; // power of two: nothing is rejected
    if (randIntFrom(4, function () { return seq2[j++]; }) !== 3) fail("power of two range");
    var seen = [0, 0, 0, 0, 0, 0, 0];
    for (var k = 0; k < 7000; k++) { var r = randInt(7); if (r < 0 || r > 6) fail("range"); seen[r]++; }
    if (seen.some(function (c) { return c < 800 || c > 1200; })) fail("distribution " + seen);
    // Entropy maths: 26 letters ^ 10 = 47.004 bits; require lower+digit at length 2: 36^2-26^2-10^2 = 520.
    if (Math.abs(passwordPlan({ lower: true, length: 10 }).bits - 10 * Math.log2(26)) > 1e-9) fail("entropy plain");
    if (countValid(36, [26, 10], 2) !== 520n) fail("inclusion-exclusion");
    if (Math.abs(passwordPlan({ lower: true, digits: true, require: true, length: 2 }).bits - Math.log2(520)) > 1e-9) fail("entropy require");
    if (Math.abs(log2Big(2n ** 200n * 3n) - (200 + Math.log2(3))) > 1e-9) fail("log2 big");
    // Look-alikes and custom exclusions never appear; required sets always appear.
    var opt = { length: 64, lower: true, upper: true, digits: true, symbols: true, lookalike: true, require: true, exclude: "xyz#" };
    var plan = passwordPlan(opt);
    for (var n = 0; n < 300; n++) {
      var pw = makePassword(opt, plan);
      if (pw.length !== 64 || /[Il1|O0oxyz#]/.test(pw)) fail("excluded char in " + pw);
    }
    var short = { length: 8, lower: true, upper: true, digits: true, symbols: true, lookalike: true, require: true };
    var sp = passwordPlan(short);
    for (var m = 0; m < 300; m++) {
      var s = makePassword(short, sp);
      if (!(/[a-z]/.test(s) && /[A-Z]/.test(s) && /[2-9]/.test(s) && /[^A-Za-z0-9]/.test(s))) fail("missing set in " + s);
    }
    // Passphrase: right number of real words; entropy = words * log2(list size).
    if (WORDS.length < 2000) fail("word list too small: " + WORDS.length);
    var ph = makePhrase({ words: 5, sep: "-", cap: false, addnum: false }).split("-");
    if (ph.length !== 5 || ph.some(function (w) { return WORDS.indexOf(w) < 0; })) fail("phrase words");
    if (Math.abs(phraseBits({ words: 6 }) - 6 * Math.log2(WORDS.length)) > 1e-9) fail("phrase bits");
    if (!/\d/.test(makePhrase({ words: 4, sep: " ", addnum: true }))) fail("phrase number");
    return ok;
  };
})();
