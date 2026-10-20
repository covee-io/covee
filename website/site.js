// Copy buttons for commands. A button with data-copy copies the element it
// names; every shell block in the guide gets its own button. Comments after
// a command are left out, since zsh would pass them on as arguments.
(() => {
  function copy(button, source) {
    const text = source.textContent.replace(/ {2,}# .*$/gm, '').replace(/\s+$/, '');
    const show = label => {
      button.textContent = label;
      setTimeout(() => { button.textContent = 'Copy'; }, 1600);
    };
    const select = () => {
      const range = document.createRange();
      range.selectNodeContents(source);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      show('Selected');
    };
    if (!navigator.clipboard) return select();
    navigator.clipboard.writeText(text).then(() => show('Copied'), select);
  }

  for (const button of document.querySelectorAll('button[data-copy]')) {
    const source = document.getElementById(button.dataset.copy);
    if (source) button.addEventListener('click', () => copy(button, source));
  }
  for (const block of document.querySelectorAll('.prose .code')) {
    const code = block.querySelector('code.language-sh');
    if (!code) continue;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy the commands');
    button.addEventListener('click', () => copy(button, code));
    block.append(button);
  }
})();
