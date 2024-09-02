// firewall.js

import { loadSuspiciousAsns, processCSV, clearList, loadList, updateBlocklistDisplay } from './rules.js';

const selectFileButton = document.getElementById('selectFileButton');
const fileInput = document.getElementById('fileInput');

const allowlistItems = document.getElementById('allowlistItems'); //Lista dos IPs permitidos 
const blocklistItems = document.getElementById('blocklistItems');  //Lista dos IPs bloqueados
const watchlistItems = document.getElementById('watchlistItems'); // Lista de IPs sinalizados

const clearAllowlistButton = document.getElementById('clearAllowlist'); //Função de limpeza da lista de permitidos
const clearBlocklistButton = document.getElementById('clearBlocklist'); //Função de limpeza da lista de bloqueados
const clearWatchlistButton = document.getElementById('clearWatchlist'); //Função de limpeza da lista de sinalizados

const loading = document.getElementById('loading');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');

let suspiciousAsns = [];

// Definição da função updateProgress
function updateProgress(percentComplete) {
    progressBar.style.width = `${percentComplete}%`;
    progressBar.textContent = `${percentComplete}%`;
}

// Quando o usuário clica no botão, dispara o input para seleção do arquivo
selectFileButton.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', handleFileSelect);

async function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        if (file.name.endsWith('.csv') || file.type === 'text/csv') {
            await loadSuspiciousAsns(suspiciousAsns);
            progressContainer.style.display = 'block';
            await processCSV(file, suspiciousAsns, blocklistItems, allowlistItems, watchlistItems, loading, updateProgress);
        } else {
            alert('Por favor, selecione um arquivo CSV.');
        }
    } else {
        alert('Por favor, selecione um arquivo.');
    }
}

clearAllowlistButton.addEventListener('click', () => clearList(allowlistItems, 'allowlist'));
clearBlocklistButton.addEventListener('click', () => clearList(blocklistItems, 'blocklist'));
clearWatchlistButton.addEventListener('click', () => clearList(watchlistItems, 'watchlist'));

document.addEventListener('DOMContentLoaded', () => {
    loadList('allowlist', allowlistItems);
    loadList('blocklist', blocklistItems);
    updateBlocklistDisplay(blocklistItems);
    setInterval(() => updateBlocklistDisplay(blocklistItems), 1000); // Atualiza a cada segundo
});
