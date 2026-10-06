/**
 * Claude voice: a self-contained, OpenAI-free voice mode for the console.
 *
 * The browser does speech itself (Web Speech API) and Claude does the thinking
 * (/api/voice/claude), so voice runs on the Anthropic key with no OpenAI
 * dependency. It is push-to-talk: activate, speak one command, hear the reply,
 * and optionally the console acts (switch view, toggle a globe layer, fly to a
 * place). Actions are driven through the DOM, so this never touches the OpenAI
 * realtime subsystem.
 *
 * It takes over the existing MIC button only when OpenAI is not configured and
 * a Claude key is — otherwise the normal OpenAI voice path runs unchanged.
 */

import { casesVoiceApi } from '../cases/casesWorkspace.js';

const SpeechRecognitionImpl =
  typeof window !== 'undefined'
    ? window.SpeechRecognition || window.webkitSpeechRecognition
    : null;

function currentView() {
  const cases = document.getElementById('cases-workspace');
  const osint = document.getElementById('osint-workspace');
  const ti = document.getElementById('threat-intel-workspace');
  if (cases && !cases.hidden) return 'cases';
  if (osint && !osint.hidden) return 'osint';
  if (ti && !ti.hidden) return 'threat-intel';
  return 'globe';
}

function toast(message) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), 4200);
}

function speak(text) {
  try {
    const synth = window.speechSynthesis;
    if (!synth || !text) return;
    synth.cancel();
    const utter = new SpeechSynthesisUtterance(text);
    utter.rate = 1.05;
    utter.pitch = 1;
    synth.speak(utter);
  } catch {
    /* speech synthesis unavailable */
  }
}

function switchView(view) {
  document.querySelector(`#view-switch [data-view="${view}"]`)?.click();
}

function toggleLayer(name, on) {
  const needle = String(name || '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
  const rows = [...document.querySelectorAll('[data-layer-id]')];
  const match = rows.find((row) => {
    const id = String(row.dataset.layerId || '').replace(/[^a-z0-9]/g, '');
    const label = (row.querySelector('.data-name')?.textContent || '')
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
    return id.includes(needle) || label.includes(needle) || needle.includes(id);
  });
  if (!match) return false;
  const btn = match.querySelector('.data-toggle-btn');
  if (!btn) return false;
  const state = btn.getAttribute('data-feed-state');
  const isOn = state && state !== 'off';
  if (on !== isOn) btn.click();
  return true;
}

function flyTo(place) {
  const input = document.getElementById('location-search');
  if (!input) return false;
  input.value = place;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(
    new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }),
  );
  return true;
}

async function executeAction(action) {
  const cases = casesVoiceApi();
  switch (action?.type) {
    case 'switch_view':
      if (['globe', 'threat-intel', 'osint', 'cases'].includes(action.view))
        switchView(action.view);
      break;
    case 'toggle_layer':
      if (!toggleLayer(action.layer, action.on !== false))
        toast(`No layer matching "${action.layer}".`);
      break;
    case 'fly_to':
      if (action.place) flyTo(action.place);
      break;
    case 'case_new':
      await cases?.newCase(action.name);
      break;
    case 'case_add': {
      const r = await cases?.addEntity(action.entity);
      if (r && !r.added && r.reason === 'unknown')
        toast(`No entity matching "${action.entity}".`);
      break;
    }
    case 'case_expand': {
      const r = await cases?.expand(action.entity);
      if (r && !r.ok) toast('No matching node to expand.');
      break;
    }
    case 'case_remove':
      if (cases && !cases.remove(action.entity))
        toast(`No node matching "${action.entity}".`);
      break;
    default:
      break;
  }
}

/**
 * Mount the Claude voice fallback on the MIC button. It intercepts the MIC
 * click (capture phase) only when OpenAI is absent and Claude is present.
 */
export function mountClaudeVoice() {
  const button = document.getElementById('gev-voice-button');
  if (!button) return;

  let openaiSet = false;
  let claudeSet = false;
  let resolved = false;
  let active = false;
  let recognition = null;

  Promise.all([
    fetch('/api/setup/status')
      .then((r) => r.json())
      .catch(() => ({})),
    fetch('/api/voice/status')
      .then((r) => r.json())
      .catch(() => ({})),
  ]).then(([setup, voice]) => {
    openaiSet = Boolean((setup.keys || []).find((k) => k.id === 'openai')?.set);
    claudeSet = Boolean(voice.available);
    resolved = true;
  });

  const claudeShouldHandle = () => resolved && !openaiSet && claudeSet;

  function setState(label) {
    const labelEl = button.querySelector('.gev-mic-label');
    if (labelEl) labelEl.textContent = label;
    button.classList.toggle('claude-voice-live', active);
  }

  function stop() {
    active = false;
    try {
      recognition?.stop();
    } catch {
      /* already stopped */
    }
    setState('ON/OFF');
  }

  async function handle(transcript) {
    toast(`“${transcript}”`);
    setState('…');
    try {
      const res = await fetch('/api/voice/claude', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transcript, context: { view: currentView() } }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        const message =
          body.error === 'no_key'
            ? 'Add an Anthropic key in POWER UP to use voice.'
            : 'The voice service is unavailable right now.';
        toast(message);
        speak(message);
        return;
      }
      if (body.speech) {
        toast(body.speech);
        speak(body.speech);
      }
      const actions = body.actions || [];
      for (const action of actions) await executeAction(action);
      // If the model acted without words, give a brief spoken confirmation.
      if (!body.speech && actions.length) speak('Done.');
    } catch {
      speak('Sorry, I could not reach the voice service.');
    } finally {
      active = false;
      setState('ON/OFF');
    }
  }

  function start() {
    if (!SpeechRecognitionImpl) {
      const message = 'Voice needs a Chromium browser with speech recognition.';
      toast(message);
      speak(message);
      return;
    }
    recognition = new SpeechRecognitionImpl();
    recognition.lang = 'en-US';
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;
    recognition.onresult = (event) => {
      const transcript = event.results?.[0]?.[0]?.transcript?.trim();
      active = false;
      if (transcript) handle(transcript);
      else setState('ON/OFF');
    };
    recognition.onerror = (event) => {
      active = false;
      setState('ON/OFF');
      if (
        event.error === 'not-allowed' ||
        event.error === 'service-not-allowed'
      )
        toast('Microphone permission is needed for voice.');
    };
    recognition.onend = () => {
      if (active) {
        active = false;
        setState('ON/OFF');
      }
    };
    try {
      recognition.start();
      active = true;
      setState('LISTENING');
      toast('Listening — say a command.');
    } catch {
      active = false;
      setState('ON/OFF');
    }
  }

  button.addEventListener(
    'click',
    (event) => {
      if (!claudeShouldHandle()) return; // let the normal OpenAI path run
      event.preventDefault();
      event.stopImmediatePropagation();
      if (active) stop();
      else start();
    },
    true, // capture phase: run before the realtime handler
  );
}
