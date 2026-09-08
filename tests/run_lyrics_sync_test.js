const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "app.py"), "utf8");
const htmlMatch = source.match(/INDEX_HTML = r"""([\s\S]*?)"""\n\nif __name__/);
assert.ok(htmlMatch, "embedded HTML was not found");
const html = htmlMatch[1];

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} was not found`);
  const bodyStart = html.indexOf("{", start);
  let depth = 0;
  for (let i = bodyStart; i < html.length; i += 1) {
    if (html[i] === "{") depth += 1;
    if (html[i] === "}" && --depth === 0) return html.slice(start, i + 1);
  }
  throw new Error(`${name} is incomplete`);
}

const sandbox = {};
vm.runInNewContext([
  extractFunction("isStaleStateTimestamp"),
  extractFunction("shouldAllowLyricRewind"),
  extractFunction("lyricIndexFor"),
].join("\n"), sandbox);

const lines = [[10, "one"], [20, "two"], [30, "three"]];
const indexFor = sandbox.lyricIndexFor;

// A small clock correction would select the previous line, but the cursor waits
// on the current line until playback catches it and then advances normally.
assert.equal(indexFor(lines, 19.5, 1, false), 1);
assert.equal(indexFor(lines, 20.0, 1, false), 1);
assert.equal(indexFor(lines, 29.9, 1, false), 1);
assert.equal(indexFor(lines, 30.0, 1, false), 2);

// An explicit rewind/seek can move backward, including before the first line.
assert.equal(indexFor(lines, 19.5, 1, true), 0);
assert.equal(indexFor(lines, 5.0, 1, true), -1);

assert.equal(sandbox.shouldAllowLyricRewind(20.3, 19.7, 5), false);
assert.equal(sandbox.shouldAllowLyricRewind(45, 12, 5), true);
assert.equal(sandbox.shouldAllowLyricRewind(20, 15, 5), true);
assert.equal(sandbox.isStaleStateTimestamp(100, 100), true);
assert.equal(sandbox.isStaleStateTimestamp(99, 100), true);
assert.equal(sandbox.isStaleStateTimestamp(101, 100), false);
assert.equal(sandbox.isStaleStateTimestamp(99, NaN), false);

class ClassList {
  constructor() { this.names = new Set(); }
  add(...names) { names.forEach((name) => this.names.add(name)); }
  remove(...names) { names.forEach((name) => this.names.delete(name)); }
  contains(name) { return this.names.has(name); }
  toggle(name, force) {
    const enabled = force === undefined ? !this.contains(name) : !!force;
    if (enabled) this.add(name); else this.remove(name);
    return enabled;
  }
}

class Element {
  constructor(id = "") {
    this.id = id;
    this.style = {};
    this.classList = new ClassList();
    this.children = [];
    this.dataset = {};
    this.offsetTop = 0;
    this.offsetHeight = 20;
    this.textContent = "";
    this._innerHTML = "";
  }
  set innerHTML(value) { this._innerHTML = value; this.children = []; }
  get innerHTML() { return this._innerHTML; }
  appendChild(child) {
    child.offsetTop = this.children.length * 20;
    this.children.push(child);
    return child;
  }
  after() {}
  closest() { return null; }
  querySelectorAll() { return []; }
}

async function runBrowserIntegration() {
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new Element(id));
    return elements.get(id);
  };
  let nowMs = 100_000;
  let responseState = null;
  let fetchImpl = async (url) => {
    const target = String(url);
    if (target === "api/state") return {ok: true, json: async () => responseState};
    if (target.startsWith("api/prefs?")) {
      return {ok: true, json: async () => ({source: "auto", offset: 0})};
    }
    throw new Error(`unexpected request: ${target}`);
  };
  const rafCallbacks = [];
  const document = {
    hidden: false,
    documentElement: new Element("html"),
    getElementById: getElement,
    createElement: () => new Element(),
    addEventListener() {},
  };
  const context = vm.createContext({
    console,
    document,
    window: {matchMedia: () => ({matches: false, addEventListener() {}})},
    location: {search: ""},
    localStorage: {getItem: () => null, setItem() {}, removeItem() {}},
    performance: {now: () => nowMs},
    requestAnimationFrame: (callback) => { rafCallbacks.push(callback); return rafCallbacks.length; },
    setTimeout: () => 1,
    clearTimeout() {},
    URLSearchParams,
    Date,
    fetch: (...args) => fetchImpl(...args),
  });

  const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(scriptMatch, "embedded script was not found");
  const browserScript = scriptMatch[1].replace("requestAnimationFrame(tick); runPoll();", "");
  vm.runInContext(browserScript, context, {filename: "embedded-index.js"});
  const run = (code) => vm.runInContext(code, context);
  context.songLoads = [];
  context.savedOnNewSong = run("onNewSong");
  run("onNewSong=(d,generation)=>songLoads.push({title:d.title,generation})");

  run(`
    st={duration:40}; base={elapsed:18.9,at:performance.now()/1000,playing:false}; curOffset=0;
    setLyrics([[10,"one"],[20,"two"],[30,"three"]],[],false);
    curIdx=1; document.getElementById("scroll").children[1].classList.add("cur");
    tick();
  `);
  assert.equal(run("curIdx"), 1, "a small correction must hold the current line");
  assert.equal(getElement("scroll").children[1].classList.contains("cur"), true);

  run("base={elapsed:29.4,at:performance.now()/1000,playing:false}; tick();");
  assert.equal(run("curIdx"), 2, "the cursor must advance after playback catches up");

  run("allowLyricRewind=true; base={elapsed:4,at:performance.now()/1000,playing:false}; tick();");
  assert.equal(run("curIdx"), -1, "a real rewind can move before the first lyric");
  assert.equal(getElement("scroll").children.some((line) => line.classList.contains("cur")), false,
    "rewinding before the first line must remove the old highlight");

  // Manual offset changes intentionally bypass the one-way cursor guard.
  run(`
    base={elapsed:19.8,at:performance.now()/1000,playing:false}; curOffset=0; curIdx=1;
    document.getElementById("scroll").children[1].classList.add("cur");
    document.getElementById("op").onclick(); tick();
  `);
  assert.equal(run("curIdx"), 0);

  // A whole stale response is discarded, even if it belongs to another song.
  run(`
    curKey="New|Artist"; curTitle="New"; curArtist="Artist";
    st={title:"New",artist:"Artist",duration:60,playing:true};
    base={elapsed:42,at:performance.now()/1000,playing:true}; lastStateTs=101;
  `);
  responseState = {ok: true, online: true, title: "Old", artist: "Artist", duration: 60,
    elapsed: 10, playing: true, ts: 100};
  await context.poll();
  assert.equal(run("curKey"), "New|Artist");
  assert.equal(run("st.title"), "New");
  assert.equal(run("base.elapsed"), 42);

  // If visibility changes create overlapping polls, a late older response cannot
  // overwrite the newer result, including with an offline response that has no ts.
  let resolveOld;
  let resolveNew;
  let fetchCount = 0;
  fetchImpl = async (url) => {
    assert.equal(String(url), "api/state");
    return new Promise((resolve) => {
    fetchCount += 1;
    if (fetchCount === 1) resolveOld = resolve; else resolveNew = resolve;
    });
  };
  const oldPoll = context.poll();
  const newPoll = context.poll();
  resolveNew({ok: true, json: async () => ({ok: true, online: true, title: "Newest", artist: "Artist",
    duration: 60, elapsed: 8, playing: true, ts: 105})});
  await newPoll;
  resolveOld({ok: true, json: async () => ({ok: true, online: false})});
  await oldPoll;
  assert.equal(run("st.title"), "Newest");
  assert.equal(run("curKey"), "Newest|Artist");
  assert.equal(context.songLoads.filter((load) => load.title === "Newest").length, 1);

  // Going offline clears the identity as well as the lines. Resuming the same
  // recording must therefore start a new lyric generation.
  fetchImpl = async (url) => {
    assert.equal(String(url), "api/state");
    return {ok: true, json: async () => responseState};
  };
  responseState = {ok: true, online: false};
  await context.poll();
  assert.equal(run("curKey"), "");
  responseState = {ok: true, online: true, title: "Newest", artist: "Artist",
    duration: 60, elapsed: 9, playing: true, ts: 106};
  await context.poll();
  assert.equal(run("curKey"), "Newest|Artist");
  assert.equal(context.songLoads.filter((load) => load.title === "Newest").length, 2);

  // Failed state polls have to reach the screen. Before the first success the
  // placeholder still reads "waiting for playback", which looks like an idle car
  // rather than a request that never landed.
  const stateFetch = fetchImpl;

  // A non-2xx reply: a proxy error page or a rate-limit page.
  fetchImpl = async () => ({ok: false, status: 503, json: async () => ({})});
  run('st=null; stateFailures=0; document.getElementById("hint").textContent="waiting";');
  await context.poll();
  assert.match(getElement("hint").textContent, /503/,
    "a failed state poll must replace the waiting placeholder");

  // A 200 whose body is HTML - an error page or a login form - so json() rejects.
  fetchImpl = async () => ({ok: true, json: async () => {
    throw new SyntaxError("Unexpected token < in JSON at position 0");
  }});
  run('st=null; stateFailures=0; document.getElementById("hint").textContent="waiting";');
  await context.poll();
  assert.match(getElement("hint").textContent, /JSON/,
    "a non-JSON body must be reported, not swallowed");

  // With a song already on screen a single blip stays quiet: the lyrics keep
  // scrolling on the local clock and there is nothing to act on yet.
  run('st={title:"New",artist:"Artist",duration:60,playing:true}; stateFailures=0;'
    + ' document.getElementById("hint").textContent="";');
  await context.poll();
  assert.equal(getElement("hint").textContent, "",
    "one failed poll must not interrupt a song that is already playing");
  const failThreshold = run("STATE_FAIL_HINT_AFTER");
  for (let i = 1; i < failThreshold; i += 1) await context.poll();
  assert.match(getElement("hint").textContent, /JSON/,
    "repeated failures must surface even while a song is on screen");

  fetchImpl = stateFetch;
  run('stateFailures=0;');

  // Fresh small regressions re-anchor the clock but keep the lyric cursor buffered.
  nowMs = 103_000;
  run(`
    curKey="New|Artist"; st={title:"New",artist:"Artist",duration:60,playing:true};
    base={elapsed:20,at:100,playing:true}; lastStateTs=101; curOffset=0;
    setLyrics([[10,"one"],[23,"two"],[30,"three"]],[],false);
    curIdx=1; document.getElementById("scroll").children[1].classList.add("cur");
  `);
  responseState = {ok: true, online: true, title: "New", artist: "Artist", duration: 60,
    elapsed: 22, playing: true, ts: 107};
  await context.poll();
  assert.equal(run("base.elapsed"), 22, "fresh elapsed must still calibrate the clock");
  run("tick()");
  assert.equal(run("curIdx"), 1, "fresh clock jitter must not move to the prior line");

  nowMs = 103_100;
  responseState = {ok: true, online: true, title: "New", artist: "Artist", duration: 60,
    elapsed: 22, playing: false, ts: 108};
  await context.poll();
  assert.equal(run("allowLyricRewind"), false, "pausing must not bypass the jitter buffer");
  run("tick()");
  assert.equal(run("curIdx"), 1);

  responseState = {ok: true, online: true, title: "New", artist: "Artist", duration: 60,
    elapsed: 5, playing: false, ts: 109};
  await context.poll();
  assert.equal(run("allowLyricRewind"), true, "a large backward seek must allow relocation");
  run("tick()");
  assert.equal(run("curIdx"), -1);

  // A slow lyric response for the previous song cannot overwrite the newer one.
  run("onNewSong=savedOnNewSong");
  let resolveFirstLyrics;
  let resolveSecondLyrics;
  let lyricFetchCount = 0;
  fetchImpl = async (url) => {
    assert.ok(String(url).startsWith("api/lyrics?"));
    return new Promise((resolve) => {
      lyricFetchCount += 1;
      if (lyricFetchCount === 1) resolveFirstLyrics = resolve;
      else resolveSecondLyrics = resolve;
    });
  };
  run(`
    curKey="First|Artist"; curTitle="First"; curArtist="Artist"; curSource="auto";
    st={title:"First",artist:"Artist",duration:60,playing:true};
  `);
  const firstLyrics = context.loadLyrics();
  run(`
    curKey="Second|Artist"; curTitle="Second"; curArtist="Artist"; curSource="auto";
    st={title:"Second",artist:"Artist",duration:60,playing:true}; songGeneration+=1;
  `);
  const secondLyrics = context.loadLyrics();
  resolveSecondLyrics({ok: true, json: async () => ({
    ok: true, found: true, source: "lrclib",
    lines: [[1, "second one"], [2, "second two"], [3, "second three"], [4, "second four"]],
  })});
  await secondLyrics;
  resolveFirstLyrics({ok: true, json: async () => ({
    ok: true, found: true, source: "lrclib",
    lines: [[1, "first one"], [2, "first two"], [3, "first three"], [4, "first four"]],
  })});
  await firstLyrics;
  assert.equal(run("lyrics[0][1]"), "second one");

  // A slow candidate response for the previous song cannot repopulate the
  // source picker after a newer song has already loaded its candidates.
  let resolveFirstCandidates;
  let resolveSecondCandidates;
  let candidateFetchCount = 0;
  fetchImpl = async (url) => {
    assert.ok(String(url).startsWith("api/candidates?"));
    return new Promise((resolve) => {
      candidateFetchCount += 1;
      if (candidateFetchCount === 1) resolveFirstCandidates = resolve;
      else resolveSecondCandidates = resolve;
    });
  };
  run(`
    curKey="First|Artist"; curTitle="First"; curArtist="Artist";
    st={title:"First",artist:"Artist",duration:60}; candidates=[]; candLoaded=false; candLoading=false;
  `);
  const firstCandidates = context.loadCandidates();
  run(`
    curKey="Second|Artist"; curTitle="Second"; curArtist="Artist";
    st={title:"Second",artist:"Artist",duration:60}; songGeneration+=1;
  `);
  const secondCandidates = context.loadCandidates();
  resolveSecondCandidates({ok: true, json: async () => ({
    ok: true,
    candidates: [{id: "lrclib:second", source: "lrclib", title: "Second", artist: "Artist"}],
  })});
  await secondCandidates;
  resolveFirstCandidates({ok: true, json: async () => ({
    ok: true,
    candidates: [{id: "lrclib:first", source: "lrclib", title: "First", artist: "Artist"}],
  })});
  await firstCandidates;
  assert.equal(run("candidates[0].title"), "Second");

  // Translation requests are tied to the lyric generation as well. A late
  // translation for the prior song must not be applied to the current lines.
  let resolveFirstTranslation;
  let resolveSecondTranslation;
  let translationFetchCount = 0;
  fetchImpl = async (url) => {
    assert.equal(String(url), "api/translate");
    return new Promise((resolve) => {
      translationFetchCount += 1;
      if (translationFetchCount === 1) resolveFirstTranslation = resolve;
      else resolveSecondTranslation = resolve;
    });
  };
  run(`
    curKey="First|Artist"; curTitle="First"; curArtist="Artist"; songGeneration+=1; showTrans=true;
    setLyrics([[1,"first one"],[2,"first two"],[3,"first three"],[4,"first four"]],[],true);
  `);
  const firstTranslation = context.loadTranslations();
  run(`
    curKey="Second|Artist"; curTitle="Second"; curArtist="Artist"; songGeneration+=1;
    setLyrics([[1,"second one"],[2,"second two"],[3,"second three"],[4,"second four"]],[],true);
  `);
  const secondTranslation = context.loadTranslations();
  resolveSecondTranslation({ok: true, json: async () => ({
    ok: true, trans: ["second translated", "two", "three", "four"],
  })});
  await secondTranslation;
  resolveFirstTranslation({ok: true, json: async () => ({
    ok: true, trans: ["first translated", "two", "three", "four"],
  })});
  await firstTranslation;
  assert.equal(run("translations[0]"), "second translated");
  assert.equal(run("transKey"), "Second|Artist");
  assert.equal(getElement("trbtn").textContent, "翻译");

  // Mock mode must not depend on a backend lyric miss to reveal its synthetic
  // lines; loadLyrics exits through the in-browser demo path.
  let mockRendered = null;
  const mockElement = {textContent: ""};
  const mockSandbox = {
    MOCK: true,
    MOCK_LINES: [[1, "demo one"], [2, "demo two"]],
    MOCK_DURATION: 20,
    lyricRequestId: 0,
    curKey: "Demo|Artist",
    curTitle: "Demo",
    curArtist: "Artist",
    curSource: "auto",
    st: {duration: 20},
    lyricInfo: {},
    showTrans: false,
    updateInfo() {},
    setLyrics(lines) { mockRendered = lines; },
    loadTranslations() {},
    $() { return mockElement; },
    Math,
    URLSearchParams,
  };
  vm.runInNewContext("async " + extractFunction("loadLyrics"), mockSandbox);
  await mockSandbox.loadLyrics();
  assert.deepEqual(mockRendered, mockSandbox.MOCK_LINES);

  console.log("lyrics sync browser integration tests passed");
}

runBrowserIntegration().then(() => {
  console.log("lyrics sync buffering tests passed");
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
