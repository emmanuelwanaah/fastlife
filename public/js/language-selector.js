(() => {
  const englishToFrench = {
    'Language': 'Langue', 'Home': 'Accueil', 'Explore': 'Explorer', 'Wishlist': 'Liste de souhaits', 'Wishlists': 'Listes de souhaits', 'Trips': 'Voyages', 'Bookings': 'Réservations', 'My Bookings': 'Mes réservations', 'My Wishlist': 'Ma liste de souhaits', 'Activity': 'Activité', 'Activities': 'Activités', 'Ticket': 'Billet', 'Sign In': 'Se connecter', 'Sign Up': "S'inscrire", 'Dashboard': 'Tableau de bord', 'Categories': 'Catégories', 'Users': 'Utilisateurs', 'Experience': 'Expérience', 'Add Activity': 'Ajouter une activité', 'Travel Platform Admin': 'Administration de la plateforme de voyage',
    'Add New Category': 'Ajouter une catégorie', 'Category Details': 'Détails de la catégorie', 'Enter the details for the new category you want to add.': 'Saisissez les détails de la nouvelle catégorie à ajouter.', 'Category Name': 'Nom de la catégorie', 'Description': 'Description', 'Image URL': "URL de l'image", 'Save Category': 'Enregistrer la catégorie', 'Add New Experience': 'Ajouter une expérience', 'Experience Title': "Titre de l'expérience", 'Location': 'Lieu', 'Category': 'Catégorie', 'Rating (0.0 - 5.0)': 'Note (0,0 - 5,0)', 'Duration (minutes)': 'Durée (minutes)', 'Price (USD)': 'Prix (USD)', 'Save Experience': "Enregistrer l'expérience",
    'Complete Your Payment': 'Finalisez votre paiement', 'Total:': 'Total :', 'Pay Now': 'Payer maintenant', 'Your Trip': 'Votre voyage', 'Date & Participants': 'Date et participants', 'Select Day': 'Choisissez un jour', 'Select Date': 'Choisissez une date', 'Number of Persons': 'Nombre de personnes', '1 Person': '1 personne', '2 Persons': '2 personnes', '3 Persons': '3 personnes', '4 Persons': '4 personnes', '5 Persons': '5 personnes', 'Select Time': "Choisissez l'heure", '-- Select Time --': "-- Choisissez l'heure --", 'Selected Date: ...': 'Date sélectionnée : ...', 'Trip Summary': 'Récapitulatif du voyage', 'Subtotal': 'Sous-total', 'Loading...': 'Chargement...', 'Continue to Confirmation': 'Continuer vers la confirmation', 'Search': 'Rechercher', 'Your trip is confirmed!': 'Votre voyage est confirmé !', 'Thank you for booking with FastlifeTravel. Below are your confirmed bookings.': 'Merci d’avoir réservé avec FastlifeTravel. Voici vos réservations confirmées.',
    'Settings': 'Paramètres', 'Profile Settings': 'Paramètres du profil', 'Name': 'Nom', 'Notifications': 'Notifications', 'Email Notifications': 'Notifications par e-mail', 'Receive updates about your trips and promotions via email.': 'Recevez par e-mail des nouvelles de vos voyages et de nos promotions.', 'SMS Notifications': 'Notifications par SMS', 'Get important alerts and reminders via SMS.': 'Recevez les alertes et rappels importants par SMS.', 'Manage Sessions': 'Gérer les sessions', 'Review and manage your active sessions.': 'Consultez et gérez vos sessions actives.', 'Help & Support': 'Aide et assistance', 'FAQs': 'FAQ', 'Contact Support': "Contacter l'assistance", 'Log Out': 'Se déconnecter', 'Book Now': 'Réserver', 'About': 'À propos', 'Terms': 'Conditions', 'Privacy': 'Confidentialité', 'Site Map': 'Plan du site', '@2024 AdventureTime. All rights reserved.': '@2024 AdventureTime. Tous droits réservés.', 'Are you sure you want to clear your entire wishlist?': 'Voulez-vous vraiment vider toute votre liste de souhaits ?', 'Proceed': 'Continuer', 'Cancel': 'Annuler', 'Please log in to view your wishlist.': 'Connectez-vous pour consulter votre liste de souhaits.', 'Failed to fetch wishlist.': 'Impossible de récupérer la liste de souhaits.',
    'Log in to your account.': 'Connectez-vous à votre compte.', 'Create new account.': 'Créer un compte.', 'Email': 'E-mail', 'Password': 'Mot de passe', 'Forgot your Email/Password?': 'E-mail ou mot de passe oublié ?', 'Login': 'Connexion', 'Invalid Email or Password.': 'E-mail ou mot de passe invalide.', "Don't have an account?": "Vous n'avez pas de compte ?", 'Create Account': 'Créer un compte', 'First Name': 'Prénom', 'Last Name': 'Nom', 'Phone': 'Téléphone', 'Create account': 'Créer un compte', 'Already have an account?': 'Vous avez déjà un compte ?', 'Log In': 'Se connecter', 'Admin Login': 'Connexion administrateur', 'Admin Email': 'E-mail administrateur', 'Invalid credentials.': 'Identifiants invalides.', 'Reset Your Password': 'Réinitialiser votre mot de passe', 'New Password': 'Nouveau mot de passe', 'Minimum 8 characters': '8 caractères minimum', 'At least one uppercase letter': 'Au moins une majuscule', 'At least one lowercase letter': 'Au moins une minuscule', 'At least one number': 'Au moins un chiffre', 'Reset Password': 'Réinitialiser le mot de passe', 'Remembered your password?': 'Vous vous souvenez de votre mot de passe ?', 'Back to Login': 'Retour à la connexion', 'Redirecting to verification page...': 'Redirection vers la page de vérification...', 'Verify Email': "Vérifier l'e-mail", 'Verify Your Email': 'Vérifiez votre adresse e-mail', 'Code has been sent to your email address': 'Un code a été envoyé à votre adresse e-mail', 'Verify': 'Vérifier', 'Resend': 'Renvoyer', 'Too many failed attempts. Please try again later.': 'Trop de tentatives échouées. Réessayez plus tard.', 'Something went wrong. Please try again.': 'Une erreur est survenue. Veuillez réessayer.', 'An error occurred. Please try again.': 'Une erreur est survenue. Veuillez réessayer.', 'Resetting...': 'Réinitialisation...', 'Eiffel Tower Guided Tour': 'Visite guidée de la tour Eiffel', 'Colosseum Tour Rome': 'Visite du Colisée à Rome', 'English': 'Anglais', 'French': 'Français'
  };
  const frenchToEnglish = Object.fromEntries(Object.entries(englishToFrench).map(([english, french]) => [french, english]));
  const originalText = new WeakMap();
  const originalAttributes = new WeakMap();
  const languageSelectors = [];
  let activeLanguage = 'en';

  function translate(source, language) {
    return language === 'fr' ? (englishToFrench[source] || source) : (frenchToEnglish[source] || source);
  }

  function translateTextNode(node, language) {
    const parent = node.parentElement;
    if (!parent || parent.closest('script, style, noscript, textarea, #fastlife-language-switcher')) return;
    if (!originalText.has(node)) originalText.set(node, node.nodeValue.trim());
    const source = originalText.get(node);
    if (!source) return;
    const result = translate(source, language);
    const nextValue = `${node.nodeValue.match(/^\s*/)[0]}${result}${node.nodeValue.match(/\s*$/)[0]}`;
    if (node.nodeValue !== nextValue) node.nodeValue = nextValue;
  }

  function translateAttributes(element, language) {
    for (const attribute of ['placeholder', 'alt', 'aria-label', 'title']) {
      if (!element.hasAttribute(attribute)) continue;
      let values = originalAttributes.get(element);
      if (!values) { values = {}; originalAttributes.set(element, values); }
      if (!(attribute in values)) values[attribute] = element.getAttribute(attribute);
      const source = values[attribute];
      const result = translate(source, language);
      if (element.getAttribute(attribute) !== result) element.setAttribute(attribute, result);
    }
  }

  function translateRoot(root, language) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) translateTextNode(node, language);
    if (root.nodeType === Node.ELEMENT_NODE) translateAttributes(root, language);
    root.querySelectorAll?.('input[placeholder], textarea[placeholder], img[alt]').forEach((element) => translateAttributes(element, language));
  }

  function preserveLanguageInInternalLinks() {
    document.querySelectorAll('a[href]').forEach((link) => {
      const href = link.getAttribute('href');
      if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) return;
      try {
        const url = new URL(href, window.location.href);
        if (url.origin === window.location.origin) {
          url.searchParams.set('lang', activeLanguage);
          link.href = `${url.pathname}${url.search}${url.hash}`;
        }
      } catch (error) {
        console.warn('Unable to preserve language in an internal link.', error);
      }
    });
  }

  function applyLanguage(language) {
    activeLanguage = language === 'fr' ? 'fr' : 'en';
    document.documentElement.lang = activeLanguage;
    document.querySelectorAll('meta[name="language"]').forEach((meta) => meta.setAttribute('content', activeLanguage));
    document.querySelectorAll('meta[property="og:locale"]').forEach((meta) => meta.setAttribute('content', activeLanguage === 'fr' ? 'fr_FR' : 'en_GB'));
    translateRoot(document.body, activeLanguage);
    languageSelectors.forEach((selector) => { selector.value = activeLanguage; });
    const selectorLabel = document.querySelector('#fastlife-language-switcher label');
    if (selectorLabel) selectorLabel.textContent = activeLanguage === 'fr' ? 'Langue' : 'Language';
    languageSelectors.forEach((selector) => selector.setAttribute('aria-label', activeLanguage === 'fr' ? 'Langue' : 'Language'));
    preserveLanguageInInternalLinks();
  }

  function setLanguage(language) {
    applyLanguage(language);
    try { localStorage.setItem('fastlife_language', activeLanguage); }
    catch (error) { console.warn('Unable to save language preference.', error); }
  }

  function createSelector(id, className) {
    const select = document.createElement('select');
    select.id = id;
    select.className = className;
    select.setAttribute('aria-label', 'Language');
    select.innerHTML = '<option value="en">🇬🇧 English</option><option value="fr">🇫🇷 Français</option>';
    select.addEventListener('change', (event) => setLanguage(event.target.value));
    return select;
  }

  function installSelector() {
    const style = document.createElement('style');
    style.textContent = `#fastlife-language-switcher{position:fixed;top:12px;right:12px;z-index:1100;display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid #dbe1e6;border-radius:999px;background:rgba(255,255,255,.97);color:#334155;box-shadow:0 2px 10px rgba(15,23,42,.1);font:500 13px/1.2 Arial,sans-serif}#fastlife-language-switcher select{max-width:132px;border:0;background:transparent;color:inherit;font:inherit}#fastlife-language-switcher select:focus{outline:2px solid #0f9f9a;outline-offset:2px}#fastlife-language-switcher .fastlife-mobile-selector{display:none}@media(max-width:640px){#fastlife-language-switcher{position:relative;inset:auto;z-index:auto;box-sizing:border-box;width:100%;min-width:0;min-height:56px;justify-content:flex-end;gap:10px;margin:0;padding:6px max(12px,env(safe-area-inset-right)) 6px max(12px,env(safe-area-inset-left));border:0;border-bottom:1px solid #e2e8f0;border-radius:0;background:#fff;box-shadow:0 2px 6px rgba(15,23,42,.06);font-family:inherit}#fastlife-language-switcher label{font-size:13px;color:#475569}#fastlife-language-switcher select{box-sizing:border-box;width:164px;max-width:calc(100vw - 100px);min-height:44px;padding:0 34px 0 12px;border:1px solid #cbd5e1;border-radius:10px;background-color:#fff;color:#1e293b;font-family:inherit;font-size:14px;font-weight:600;line-height:1.2;white-space:nowrap}#fastlife-language-switcher .fastlife-desktop-selector{display:none}#fastlife-language-switcher .fastlife-mobile-selector{display:inline-block}body>#fastlife-language-switcher{order:-1}}`;
    document.head.appendChild(style);
    const wrapper = document.createElement('div');
    wrapper.id = 'fastlife-language-switcher';
    const label = document.createElement('label');
    label.htmlFor = 'desktopLanguageSelector';
    label.textContent = 'Language';
    const desktop = createSelector('desktopLanguageSelector', 'fastlife-desktop-selector');
    const mobile = createSelector('mobileLanguageSelector', 'fastlife-mobile-selector');
    wrapper.append(label, desktop, mobile);
    document.body.insertBefore(wrapper, document.body.firstChild);
    languageSelectors.push(desktop, mobile);
  }

  function initialLanguage() {
    try { return localStorage.getItem('fastlife_language') || new URLSearchParams(location.search).get('lang') || 'en'; }
    catch (error) { return new URLSearchParams(location.search).get('lang') || 'en'; }
  }

  installSelector();
  applyLanguage(initialLanguage());
  new MutationObserver((records) => records.forEach((record) => {
    if (record.type === 'characterData') translateTextNode(record.target, activeLanguage);
    record.addedNodes?.forEach((node) => {
      if (node.nodeType === Node.TEXT_NODE) translateTextNode(node, activeLanguage);
      else if (node.nodeType === Node.ELEMENT_NODE && !node.closest('#fastlife-language-switcher')) translateRoot(node, activeLanguage);
    });
  })).observe(document.body, { childList: true, characterData: true, subtree: true });
})();