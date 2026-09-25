// PinVault dashboard — Event delegation (CSP-safe) and start-up. Loaded last: it binds the handlers every file above declared.
// Classic scripts sharing one global scope, loaded in order by index.html.

// ── CSP-safe event delegation ────────────────────────
// Inline handlers (onclick=/onchange=/onsubmit=) violate `script-src 'self'`
// from the M-05 hardening pass. Buttons/inputs/forms use `data-action="<fn>"`
// + `data-arg0..argN` attributes instead. Optional flags on the element:
//   data-stop="1"   → event.stopPropagation() before dispatch
//   data-event="1"  → append the event object as the last argument
// Dispatch is via an explicit `_actionHandlers` table (not bare window lookup)
// so injected HTML can only invoke whitelisted functions.

// Wrappers for inline expressions that combined multiple statements.
/**
 * "+" düğmesi: kapsamı seçip "Yeni Host Ekle" formunu açar.
 *
 * `loadConfig()` şart. "Manuel" sekmesi yeni host'u `currentConfig.pins`
 * listesinin üstüne ekleyip TÜM listeyi seçili kapsama yazıyor; kapsam
 * değişmişken eski kapsamın pin'leri hedef kapsama taşınırdı.
 */
async function showAddHostScoped(apiId) {
  selectedApiId = apiId;
  await loadConfig();
  showAddHost();
}
function setConfigApiTab(tabId, apiId) { configApiTab = tabId; renderConfigApiDetail(apiId); }
function renderEmptyAndHostList() { renderEmpty(); renderHostList(); }
function clickFileInput(id) { document.getElementById(id).click(); }
function updateEditHash(idx, ev) { editHashes[parseInt(idx, 10)] = ev.target.value; }
function removeEditHashEdit(idx, hostname) { editHashes.splice(parseInt(idx, 10), 1); renderEditPins(hostname); }
function removeEditHashInline(idx, hostname) { editHashes.splice(parseInt(idx, 10), 1); renderInlineEditPins(hostname); }
function addEditHashEdit(hostname) { editHashes.push(''); renderEditPins(hostname); }
function addEditHashInline(hostname) { editHashes.push(''); renderInlineEditPins(hostname); }
function setVaultEnabledChange(apiId, ev) { setVaultEnabled(apiId, ev.target.checked); }
function pagSizeChange(key, onChangeGlobalFn, ev) { pagSize(key, ev.target.value, onChangeGlobalFn); }
function setVaultUploadMode(mode) {
  const isText = mode === 'text';
  const fileGroup = document.getElementById('vault-file-group');
  const textGroup = document.getElementById('vault-text-group');
  const fileInput = document.getElementById('vault-upload-file');
  const textInput = document.getElementById('vault-upload-text');
  if (fileGroup) fileGroup.style.display = isText ? 'none' : '';
  if (textGroup) textGroup.style.display = isText ? '' : 'none';
  // Clear the inactive input so a stale value can't be submitted by accident.
  if (isText && fileInput) fileInput.value = '';
  if (!isText && textInput) textInput.value = '';
  const fileBtn = document.getElementById('vault-tab-file');
  const textBtn = document.getElementById('vault-tab-text');
  if (fileBtn) fileBtn.className = 'btn ' + (isText ? 'btn-secondary' : 'btn-primary');
  if (textBtn) textBtn.className = 'btn ' + (isText ? 'btn-primary' : 'btn-secondary');
  if (isText && textInput) textInput.focus();
}
// Localized one-line description for the selected vault encryption mode.
function vaultEncDesc(v) {
  return v === 'at_rest' ? t('encDescAtRest')
    : v === 'end_to_end' ? t('encDescE2E')
    : t('encDescPlain');
}
function updateEncDesc(ev) {
  const el = document.getElementById('vault-enc-desc');
  if (el) el.textContent = vaultEncDesc(ev.target.value);
}

const _actionHandlers = {
  clearForceAll, copyText, createConfigApi, createHostFetch, createHostGenerate,
  createHostManual, createHostUpload,
  deleteConfigApi, deleteHost, deleteVaultFile, editDeviceAcl, fetchBootstrapFromUrl,
  forceUpdateAll, generateClientCert,
  generateEnrollmentToken, generateVaultToken, loadClientDevices, loadHostConnectionHistory,
  pagGo, pagSize, regenerateBootstrapCert, regenerateSigningKey, renderApiVaultTab,
  renderConfigApiDetail, renderEditPins, renderEmpty, renderHostList, renderInlineEditPins,
  renewCertAuto, renewCertUpload, revokeClientCert, revokeVaultToken, runHealthCheck,
  rotateBootstrapToBackup, rotateHostToBackup,
  saveDefaultAcl, saveInlinePins, savePins, saveVaultFilePolicy, selectHost,
  selectHostInApi, setLang,
  setVaultEnabled, setVaultStatusFilter, showAddConfigApi, showAddHost, showCertUploadForm,
  showDeviceAclManager, showDeviceDetail, showVaultFileDetail, switchAddTab,
  showSection,
  testHostConnection, toggleApiTree, toggleBootstrapFetch, toggleBootstrapUpload,
  toggleConfigApi,
  toggleEditPins, toggleForce, toggleHostMtls, toggleMock, uploadBootstrapCert,
  uploadClientCert, uploadHostClientCert, uploadVaultFile,
  showAddHostScoped, setConfigApiTab, renderEmptyAndHostList, clickFileInput,
  updateEditHash, removeEditHashEdit, removeEditHashInline, addEditHashEdit,
  addEditHashInline, setVaultEnabledChange, pagSizeChange, setVaultUploadMode, updateEncDesc,
  // Governance (identity, approvals, audit log, live check, signing keys)
  switchAdminKey, setApprovalsTab, refreshApprovals, toggleChangeDetail, approveChange, rejectChange,
  setAuditActionFilter, toggleAuditDetail, verifyAuditChain, sendTestNotification, refreshAudit,
  uploadKeyset, liveCheckPins
};

function _collectArgs(el) {
  const args = [];
  let i = 0;
  while (el.dataset['arg' + i] !== undefined) {
    args.push(el.dataset['arg' + i]);
    i++;
  }
  return args;
}

function _resolveHandler(name) {
  const fn = _actionHandlers[name];
  if (typeof fn !== 'function') { console.warn('Unknown action:', name); return null; }
  return fn;
}

// click: optional event as LAST arg when data-event="1"
document.body.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  if (el.dataset.stop === '1') e.stopPropagation();
  const fn = _resolveHandler(el.dataset.action);
  if (!fn) return;
  beginUserAction();
  const args = _collectArgs(el);
  if (el.dataset.event === '1') args.push(e);
  fn.apply(null, args);
});

// change: event as LAST arg when data-event="1" (input handlers commonly need this.value/checked)
document.body.addEventListener('change', (e) => {
  const el = e.target.closest('[data-action-change]');
  if (!el) return;
  const fn = _resolveHandler(el.dataset.actionChange);
  if (!fn) return;
  beginUserAction();
  const args = _collectArgs(el);
  if (el.dataset.event === '1') args.push(e);
  fn.apply(null, args);
});

// submit: form handlers always receive event as the FIRST arg
// (they call e.preventDefault() internally and read inputs from the DOM)
document.body.addEventListener('submit', (e) => {
  const el = e.target.closest('[data-action-submit]');
  if (!el) return;
  const fn = _resolveHandler(el.dataset.actionSubmit);
  if (!fn) return;
  beginUserAction();
  fn.apply(null, [e].concat(_collectArgs(el)));
});

// ── Start ────────────────────────────────────────────
init();
