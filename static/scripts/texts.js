function copyToClipboard(inputElement) {
  navigator.clipboard.writeText(inputElement.value);
  alert("Copied to clipboard");
}
