// Covee local accounts: passkey sign-in and invitation setup.
// Served by the identity broker from its own origin; no inline scripts.
(function () {
  "use strict";

  function toB64u(buffer) {
    var bytes = new Uint8Array(buffer), text = "";
    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function fromB64u(value) {
    var text = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4));
    var bytes = new Uint8Array(text.length);
    for (var i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
    return bytes.buffer;
  }
  function status(message) {
    var el = document.getElementById("status");
    if (el) el.textContent = message;
  }
  function post(path, body) {
    return fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        return { ok: response.ok, status: response.status, data: data };
      });
    });
  }
  function credentialJSON(credential, assertion) {
    var r = credential.response, response = { clientDataJSON: toB64u(r.clientDataJSON) };
    if (assertion) {
      response.authenticatorData = toB64u(r.authenticatorData);
      response.signature = toB64u(r.signature);
      if (r.userHandle) response.userHandle = toB64u(r.userHandle);
    } else {
      response.attestationObject = toB64u(r.attestationObject);
      if (r.getTransports) response.transports = r.getTransports();
    }
    return {
      id: credential.id, rawId: toB64u(credential.rawId), type: credential.type, response: response,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {}
    };
  }
  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  // Sign-in page.
  var signIn = document.getElementById("passkey");
  if (signIn) {
    if (!supported()) {
      signIn.disabled = true;
      status("This browser cannot use passkeys; use your password below.");
    }
    signIn.addEventListener("click", function () {
      var state = signIn.getAttribute("data-state");
      signIn.disabled = true;
      status("Waiting for your passkey…");
      post("/identity/local/passkey/options", { state: state }).then(function (options) {
        if (!options.ok) throw new Error("Passkey sign-in is not available right now. Start again from the beginning.");
        var pk = options.data.publicKey;
        pk.challenge = fromB64u(pk.challenge);
        (pk.allowCredentials || []).forEach(function (c) { c.id = fromB64u(c.id); });
        return navigator.credentials.get({ publicKey: pk }).catch(function () {
          throw new Error("No passkey was used. Start again from the beginning to try again.");
        });
      }).then(function (credential) {
        return post("/identity/local/passkey/finish", { state: state, credential: credentialJSON(credential, true) });
      }).then(function (result) {
        if (result.ok && result.data.redirect) {
          window.location.assign(result.data.redirect);
          return;
        }
        if (result.status === 403) throw new Error("Access requires approval. Ask your operator to give the account " + (result.data.subject || "") + " access.");
        throw new Error("That passkey was not accepted. Start again from the beginning.");
      }).catch(function (error) {
        status(error.message);
      });
    });
  }

  // Invitation page: the token travels only in the URL fragment.
  if (document.getElementById("invite")) {
    var token = window.location.hash.slice(1);
    history.replaceState(null, "", window.location.pathname);
    var show = function (id) {
      ["choose", "password", "done"].forEach(function (name) {
        document.getElementById(name).hidden = name !== id;
      });
    };
    post("/identity/local/invite/info", { token: token }).then(function (info) {
      if (!info.ok) {
        status("This invitation link is not valid or has expired. Ask your operator for a new one.");
        return;
      }
      document.getElementById("who").textContent = "Account: " + info.data.email;
      status("");
      show("choose");
      if (!supported()) {
        document.getElementById("create-passkey").disabled = true;
        status("This browser cannot create passkeys; use a password instead.");
      }
    });
    document.getElementById("create-passkey").addEventListener("click", function () {
      status("Follow your device's prompt to create the passkey…");
      post("/identity/local/invite/passkey/options", { token: token }).then(function (options) {
        if (!options.ok) throw new Error("This invitation link is not valid or has expired.");
        var pk = options.data.publicKey;
        pk.challenge = fromB64u(pk.challenge);
        pk.user.id = fromB64u(pk.user.id);
        (pk.excludeCredentials || []).forEach(function (c) { c.id = fromB64u(c.id); });
        return navigator.credentials.create({ publicKey: pk }).catch(function () {
          throw new Error("No passkey was created. You can try again.");
        });
      }).then(function (credential) {
        return post("/identity/local/invite/passkey/finish", { token: token, credential: credentialJSON(credential, false) });
      }).then(function (result) {
        if (!result.ok) throw new Error("The passkey could not be saved. Ask your operator for a new invitation.");
        status("");
        show("done");
      }).catch(function (error) {
        status(error.message);
      });
    });
    document.getElementById("use-password").addEventListener("click", function () {
      post("/identity/local/invite/totp", { token: token }).then(function (result) {
        if (!result.ok) {
          status("This invitation link is not valid or has expired.");
          return;
        }
        document.getElementById("secret").textContent = result.data.secret_base32;
        if (result.data.qr_svg_data_uri) {
          var img = document.getElementById("qr");
          img.src = result.data.qr_svg_data_uri;
          img.hidden = false;
        }
        status("");
        show("password");
      });
    });
    document.getElementById("password-form").addEventListener("submit", function (event) {
      event.preventDefault();
      post("/identity/local/invite/password", {
        token: token,
        password: document.getElementById("new-password").value,
        code: document.getElementById("code").value
      }).then(function (result) {
        if (result.ok) {
          status("");
          show("done");
        } else if (result.data.error === "weak_password") {
          status(result.data.message);
        } else if (result.data.error === "invalid_code") {
          status("That code did not match. Wait for a new code in your authenticator app and try again.");
        } else {
          status("This invitation link is not valid or has expired.");
        }
      });
    });
  }
})();
