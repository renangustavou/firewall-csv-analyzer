// rules.js

//Variáveis que definem a quantidade "pontos" para cada aspecto que possa indicar um possível IP suspseito, apresentado valores maiores para aspectos que determinariam que um IP é suspeito

const CRITICIDADE = {
    suspiciousCountry: 10,
    suspiciousASN: 8,
    suspiciousDevice: 5,
    suspiciousReferer: 6,
    suspiciousURI: 7,
    httpProtocol: 4,
    rateLimitingExceeded: 15
};

const TIME_WINDOW = 60 * 1000; // Janela de tempo de 1 minuto (em milissegundos)
const MAX_REQUESTS_PER_MINUTE = 100; // Limite de 100 requisições por minuto por IP

//Esta função carrega a lista JSON de ASNs que foram apontados como suspeitos e disponibilizados na internet. 
export async function loadSuspiciousAsns(suspiciousAsns) {
    try {
        const response = await fetch('src/asn-blocklist.json');
        if (!response.ok) {
            throw new Error(`Erro HTTP: ${response.status}`);
        }
        const text = await response.text();
        const data = JSON.parse(text);
        suspiciousAsns.splice(0, suspiciousAsns.length, ...data);
    } catch (error) {
        console.error('Erro ao carregar a lista de ASNs suspeitos:', error);
    }
}
 
// Função para converter pontos dos níveis de criticidade em texto, podendo apresentar risco BAIXO (quando totalizam até 9 pontos), MÉDIO (até 18), ALTO (maior que 18 pontos)
function getCriticidadeLevel(points) {
    if (points <= 9) {
        return 'BAIXO';
    } else if (points <= 18) {
        return 'MÉDIO';
    } else {
        return 'ALTO';
    }
}

//Essa é uma função "core" que irá processar o arquivo de CSV de exemplo e com base em alguns parâmetros definidos abaixo irá classificar os IPs
export async function processCSV(file, suspiciousAsns, blocklistItems, allowlistItems, watchlistItems, loading, updateProgress) {
    if (loading && loading.style) {
        loading.style.display = 'block';
    }

    const reader = file.stream().getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let headers = [];

    // Essa const será usada para mapear todos as tentativas de acesso de cada IP
    const ipAccessLogs = new Map(); 

    //Abaixo é deifnido todos os critérios para classificar e totalizar os pontos de criticidade de cada um dos IPs

    //Nessa const foram definidos as portas que são mais críticas e mais frequentes durante tentativas de invasão
    const suspiciousPorts = new Set([21, 22, 23, 25, 53, 80, 443, 8080, 3306, 3389, 5900]);
    
    //Abaixo são os métodos HTTP que possuem maior "capacidade" de explorar e modificar durante uma tentativa de ataque
    const suspiciousMethods = new Set(['POST', 'PUT', 'DELETE', 'CONNECT', 'PATCH']);
    
    //Códigos dos países que possuem maior histórico de ataques cibernéticos
    const suspiciousCountries = new Set(['CN', 'RU', 'KR', 'IR', 'IN']);
    
    //Durante ataques é comum que os dispositivos tenham as nomenclaturas como está na linha de comando abaixo
    const suspiciousDevices = new Set(['mobile', 'unknown']);

    //Abaixo estão os principais user agents que são comumente associados a ataques
    const suspiciousUserAgents = new Set(['bot', 'spider', 'crawler', 'scanner']);

    //Sites que foram identificados previamente com o uso de HTTP (além de HTTPS)
    const suspiciousReferers = new Set(['http://www.hernandez.com/', 'http://untrustedsite.com/']);

    //Abaixo são palavras-chave que podem indicar tentativas de acesso a caminhos sensíveis na rede
    const suspiciousURIKeywords = new Set(['login', 'admin', 'wp-login', 'exploit', 'shell']);

    //Com este buffer, os IPs que forem bloqueados serão armazenados temporariamente, assim como o tamanho do lote também é definido para atualizar o DOM em determinados intervalos.
    const blocklistBuffer = []; 
    const allowlistBuffer = [];
    const BATCH_SIZE = 100;

    //Aqui é inicializado a variável para contar o total de linhas que possuem no CSV e outra variável irá conta o número de linhas que foram processadas
    let totalLines = 0; 
    let processedLines = 0;

    //Abaixo todo conteúdo do CSV inserido é lido e também o total de linhas é calculado. Adicionei -1 por conta do cabeçalho.
    const textContent = await file.text();
    totalLines = textContent.split('\n').length - 1;


    //Essa função é um segundo leitor, ele começa parando a leitura que foi feita anteriormente e "quebra" o CSV em partes para fazer sua leitura total novamente, essa função foi necessária por conta do tamanho do CSV de exemplo.
    reader.releaseLock();
    const newReader = file.stream().getReader();

    while (true) { //Neste momento é inicializado um loop que será contínuo para a leitura do arquivo até o final
        const { done, value } = await newReader.read(); //Uma parte do arquivo é lida e esta leitura é armazenada em "value", done indica se a leitura foi finalizada.
        if (done) break; //Se a leitura terminou, o loop é quebrado neste momento

        //A parte lida do arquivo é decodificada e adicionada ao buffer. O buffer então é dividido em linhas utilizando \n como delimitante. 
        buffer += decoder.decode(value, { stream: true });
        let lines = buffer.split('\n');
        buffer = lines.pop(); //A última linha do buffer é removida para garantir seja processada uma linha incompleta.

        //Essa função itera sobre cada linha completa no buffer. 
        for (const line of lines) { 
            if (!headers.length) { //Caso os cabeçalhos não forem definidos (primeira linha de dados)
                headers = line.split(','); //Divide as linhas de cabeçalhos em colunas com a vírgula

                //Então o processo continua já que na linha atual contém apenas cabeçalhos
                continue;
            }

            //Abaixo a função divide a linha em valores individuais, caso possua mais de um valor é uma linha válida. Por fim, um objeto entry é criado e ele será associado aos valores do cabeçalho
            const values = line.split(',');
            if (values.length > 1) {
                const entry = createEntry(values, headers);

                //Abaixo os IPs tem sua pontuação total de "suspeito" somadas e é definido qual o seu nível de criticidade, sendo adicionado a cada tabela correspondente dependendo de sua pontuação
                const { points, reason } = checkSuspiciousEntry(entry, ipAccessLogs, suspiciousAsns, suspiciousCountries, suspiciousDevices, suspiciousReferers, suspiciousURIKeywords);
                const criticidade = getCriticidadeLevel(points);
                const listItem = createListItem(entry, reason, criticidade);

                if (criticidade === 'ALTO') {
                    blocklistBuffer.push(listItem);
                    addToBlocklist(entry, reason);
                } else if (criticidade === 'BAIXO') {
                    allowlistBuffer.push(listItem);
                    addToAllowlist(entry);
                } else {
                    watchlistItems.appendChild(listItem); 
                }
            }

            //Com a função é incrementado o número total de linhas processadas 

            processedLines++;
            const progressPercent = (processedLines / totalLines) * 100; //A porcentagem do progresso é calculada com essa função e a barra de progresso no DOM é atualizada.
            updateProgress(progressPercent.toFixed(2));
            
             // O DOM é atualizado se o buffer atingiu o tamanho do lote definido
            if (blocklistBuffer.length >= BATCH_SIZE || allowlistBuffer.length >= BATCH_SIZE) {
                updateDOM(blocklistItems, allowlistItems, blocklistBuffer, allowlistBuffer); //As listas das tabelas são atualizadas no DOM
                
                //O buffer de bloqueados e permitidos é limpo com as funções abaixo
                blocklistBuffer.length = 0; 
                allowlistBuffer.length = 0;
                await new Promise(resolve => setTimeout(resolve, 0)); //É uma função de aguardo antes que qualquer outra operação seja realizada
            }
        }
    }

    //Após todo o processamento o DOM é atualizado com as listas abaixo. Também adicionei um atraso na exibição da lista da blocklist, pois antes estava enfrentado problemas de desempenho no site com todas as listas carregando.
    updateDOM(blocklistItems, allowlistItems, blocklistBuffer, allowlistBuffer);
    debounceUpdateBlocklistDisplay(blocklistItems)();

    if (loading && loading.style) {
        loading.style.display = 'none'; //O carregador visual do processamento é escondido quando o processo finaliza por completo
    }
}

//Nesta função um objeto de entrada é criado para mapear os valores dos cabeçalhos presentes no CSV de exemplo.
function createEntry(values, headers) {
    return {
        ip: values[headers.indexOf('ClientIP')],
        port: parseInt(values[headers.indexOf('ClientSrcPort')], 10),
        method: values[headers.indexOf('ClientRequestMethod')],
        uri: values[headers.indexOf('ClientRequestURI')],
        referer: values[headers.indexOf('ClientRequestReferer')],
        userAgent: values[headers.indexOf('ClientRequestUserAgent')],
        country: values[headers.indexOf('ClientCountry')],
        asn: values[headers.indexOf('ClientASN')],
        device: values[headers.indexOf('ClientDeviceType')],
        scheme: values[headers.indexOf('ClientRequestScheme')]
    };
}

// Função para verificar tentativas de acesso por IP
function checkRateLimiting(entry, ipAccessLogs) {
    const now = Date.now(); //Captura o momento atual

    //Caso o IP ainda não tenha sido registrado, é inicializado um registro de todos os acessos futuros deste IP
    if (!ipAccessLogs.has(entry.ip)) { 
        ipAccessLogs.set(entry.ip, []);
    }

    const accessLog = ipAccessLogs.get(entry.ip); //Os logs de tentativa de acesso do IP são buscados

    //E com essa função os registros antigos são removidos caso tenham excedido o tempo de janela que foi definido
    while (accessLog.length > 0 && now - accessLog[0] > TIME_WINDOW) {
        accessLog.shift();
    }

    // Adiciona o horário atual ao log de acessos
    accessLog.push(now);

    // Retorna true se o número de acessos ultrapassar o limite permitido por minuto
    return accessLog.length > MAX_REQUESTS_PER_MINUTE;
}

// Essa função verifica se uma entrada de log é suspeita com base nos critérios definidos anteriormente e calcula a pontuação de criticidade
function checkSuspiciousEntry(entry, ipAccessLogs, suspiciousAsns, suspiciousCountries, suspiciousDevices, suspiciousReferers, suspiciousURIKeywords) {
    let points = 0; //Os pontos são inicializados/zerados
    let reasons = []; //Uma lista das razões pra ser um endereço suspeito é criada

    // Verifica se o IP excedeu o limite de requisições, caso sim, os pontos são adicionados
    if (checkRateLimiting(entry, ipAccessLogs)) {
        points += CRITICIDADE.rateLimitingExceeded;
        reasons.push("Rate Limiting Exceeded");
    }

    // Verifica se o país de origem é suspeito
    if (suspiciousCountries.has(entry.country)) {
        points += CRITICIDADE.suspiciousCountry;
        reasons.push("País Suspeito");
    }

    // Verifica se o ASN é suspeito
    if (suspiciousAsns.includes(parseInt(entry.asn))) {
        points += CRITICIDADE.suspiciousASN;
        reasons.push("ASN Suspeito");
    }

    // Verifica se o dispositivo é suspeito
    if (suspiciousDevices.has(entry.device.toLowerCase())) {
        points += CRITICIDADE.suspiciousDevice;
        reasons.push("Dispositivo Suspeito");
    }

    // Verifica se o referer é suspeito
    if ([...suspiciousReferers].some(ref => entry.referer.includes(ref))) {
        points += CRITICIDADE.suspiciousReferer;
        reasons.push("Referer Suspeito");
    }

    // Verifica se o URI contém palavras-chave suspeitas
    if (entry.uri.split('/').some(segment => suspiciousURIKeywords.has(segment.toLowerCase()))) {
        points += CRITICIDADE.suspiciousURI;
        reasons.push("URI Suspeita");
    }

    // Verifica se o protocolo é HTTP
    if (entry.scheme === 'http') {
        points += CRITICIDADE.httpProtocol;
        reasons.push("Protocolo HTTP Inseguro");
    }

    // Retorna o total de pontos e a razão concatenada das suspeitas
    return { points, reason: reasons.join(", ") || null };
}


// Essa função  cria um elemento de linha de tabela HTML para exibir uma entrada de log com suas informações detalhadas. Também ecebe os dados do IP, o motivo pelo qual ele foi sinalizado e seu nível de criticidade.
// Após isso, cria uma linha de tabela com essas informações e retorna o elemento criado para inserção no DOM.

function createListItem(entry, reason, criticidade) {
    const listItem = document.createElement('tr'); // Cria um novo elemento de linha de tabela

    const ipCell = document.createElement('td'); // Cria uma célula para o IP e define o IP como conteúdo da linha
    ipCell.textContent = entry.ip;
    listItem.appendChild(ipCell);

    const methodCell = document.createElement('td'); // Cria uma célula para o método utilizado 
    methodCell.textContent = entry.method;
    listItem.appendChild(methodCell);

    const schemeCell = document.createElement('td'); // Cria uma célula para o esquema utilizado (HTTP/HTTPS)
    schemeCell.textContent = entry.scheme;
    listItem.appendChild(schemeCell);

    const uriCell = document.createElement('td'); // Cria uma célula para o URI que foi solicitada
    uriCell.textContent = entry.uri;
    listItem.appendChild(uriCell);

    const reasonCell = document.createElement('td'); // Cria uma célula para o motivo da sinalização
    reasonCell.textContent = reason || ''; 
    listItem.appendChild(reasonCell);

    const criticidadeCell = document.createElement('td');
    criticidadeCell.textContent = criticidade; // Exibe o nível de criticidade (BAIXO, MÉDIO, ALTO)
    listItem.appendChild(criticidadeCell);

    // Retorna a linha completa para ser inserida na tabela HTML
    return listItem;
}

// Essa função atualiza o DOM com as novas entradas de IP processadas, além de adicionar os itens da lista de bloqueio e permissão ao DOM. 
//É chamada novamente após o processamento do lote de dados que garante que as informações exibidas estão atualizadas
function updateDOM(blocklistItems, allowlistItems, blocklistBuffer, allowlistBuffer) {
    if (blocklistBuffer.length > 0) {
        blocklistItems.append(...blocklistBuffer);
    }
    if (allowlistBuffer.length > 0) {
        allowlistItems.append(...allowlistBuffer);
    }
}

// Função que adiciona um IP à lista de permitidos e o armazena no localStorage, mas antes verifica se o IP foi adicionado anteriormente
export function addToAllowlist(entry) {
    const allowlist = JSON.parse(localStorage.getItem('allowlist') || '[]');
    if (!allowlist.some(item => item.ip === entry.ip)) {
        allowlist.push({
            ip: entry.ip,
            method: entry.method,
            scheme: entry.scheme,
            uri: entry.uri
        });
        localStorage.setItem('allowlist', JSON.stringify(allowlist));
    }
}

// Função que adiciona um IP à lista de bloqueio com o motivo e o timestamp, por fim também armazena no localStorage
export function addToBlocklist(entry, reason) {
    const blocklist = JSON.parse(localStorage.getItem('blocklist') || '[]');
    const now = Date.now();
    blocklist.push({ ...entry, timestamp: now, reason });
    localStorage.setItem('blocklist', JSON.stringify(blocklist));
}

// Função que verifica se um IP está atualmente bloqueado e determina se o seu período de bloqueio ainda está válido (12 horas)
export function isBlocked(ip) {
    const blocklist = JSON.parse(localStorage.getItem('blocklist') || '[]');
    const now = Date.now();
    return blocklist.some(entry => entry.ip === ip && now - entry.timestamp < 12 * 60 * 60 * 1000);
}

// A função abaixo otimiza a atualização da lista de bloqueio no DOM para evitar solicitações repetidas
// Com o uso do debounce, ele adia a execução de uma função para um momento posterior quando ela não é chamada repetidamente.
function debounceUpdateBlocklistDisplay(blocklistItems) {
    let timeout;
    return function() {
        clearTimeout(timeout); // Limpa timeout anterior
        timeout = setTimeout(() => updateBlocklistDisplay(blocklistItems), 500);
    };
}

// A exibição da lista de bloqueio é atualizada no DOM com as informações mais recentes
// Também carrega a lista de bloqueados do localStorage, cria elementos de tabela HTML para cada IP bloqueado e os adiciona ao DOM.

export function updateBlocklistDisplay(blocklistItems) {
    const blocklist = JSON.parse(localStorage.getItem('blocklist') || '[]');
    const now = Date.now(); // Obtém o timestamp atual
    blocklistItems.innerHTML = '';
    blocklist.forEach(entry => {
        const listItem = document.createElement('tr'); // Cria um novo elemento de linha de tabela

        const ipCell = document.createElement('td'); // Cria uma célula para o IP
        ipCell.textContent = entry.ip;
        listItem.appendChild(ipCell);

        const methodCell = document.createElement('td'); // Cria uma célula para o método
        methodCell.textContent = entry.method;
        listItem.appendChild(methodCell);

        const schemeCell = document.createElement('td'); // Cria uma célula para o esquema que foi utilizado 
        schemeCell.textContent = entry.scheme;
        listItem.appendChild(schemeCell);

        const uriCell = document.createElement('td'); // Cria uma célula para a URI que foi solicitada
        uriCell.textContent = entry.uri;
        listItem.appendChild(uriCell);

        const reasonCell = document.createElement('td'); // Cria uma célula para a razão de bloqueio 
        reasonCell.textContent = entry.reason || 'N/A'; 
        listItem.appendChild(reasonCell);

        const criticidadeCell = document.createElement('td');
        criticidadeCell.textContent = getCriticidadeLevel(entry.points); // Exibe a criticidade (BAIXO, MÉDIO, ALTO)
        listItem.appendChild(criticidadeCell);

        const timeRemainingCell = document.createElement('td'); // Cria uma célula para o tempo restante de bloqueio
        const timeRemaining = Math.max(0, 12 * 60 * 60 * 1000 - (now - entry.timestamp)); // O tempo restante é calculada em milissegundos
        const hours = Math.floor(timeRemaining / (1000 * 60 * 60)); // Convertido para horas
        const minutes = Math.floor((timeRemaining % (1000 * 60 * 60)) / (1000 * 60)); // Convertido para minutos
        const seconds = Math.floor((timeRemaining % (1000 * 60)) / 1000); // Convertido para segundos
        const timeString = `${hours}h ${minutes}m ${seconds}s`; // Formata o tempo restante utlizando as variáveis definidas acima
        timeRemainingCell.textContent = timeString;
        listItem.appendChild(timeRemainingCell); // A célula é adicionada na linha

        blocklistItems.appendChild(listItem);
    });
}

// Função que limpa uma lista (de permitidos ou bloqueados) do DOM e do localStorage após confirmação do usuário
export function clearList(listElement, listId) {
    if (confirm(`Você tem certeza de que deseja limpar a ${listId}?`)) {
        listElement.innerHTML = '';
        localStorage.removeItem(listId);
    }
}

// Função que carrega uma lista específica (de permitidos ou bloqueados) do localStorage e a exibe no DOM
export function loadList(listId, listElement) {
    const data = JSON.parse(localStorage.getItem(listId) || '[]'); // Carrega a lista do localStorage ou inicializa uma nova lista vazia
    listElement.innerHTML = '';

    data.forEach(item => {
        const listItem = document.createElement('tr'); // Cria um novo elemento de linha de tabela

        const ipCell = document.createElement('td'); // Cria uma célula para o IP
        ipCell.textContent = item.ip;
        listItem.appendChild(ipCell);

        const methodCell = document.createElement('td'); // Cria uma célula para o método utilizado
        methodCell.textContent = item.method;
        listItem.appendChild(methodCell);

        const schemeCell = document.createElement('td'); // Cria uma célula para o esquema utilizado
        schemeCell.textContent = item.scheme;
        listItem.appendChild(schemeCell);

        const uriCell = document.createElement('td'); // Cria uma célula para o URI que foi solicitado
        uriCell.textContent = item.uri;
        listItem.appendChild(uriCell);

        const reasonCell = document.createElement('td'); // Cria uma célula para o motivo que está sendo sinalizdo
        reasonCell.textContent = item.reason || 'N/A';
        listItem.appendChild(reasonCell);

        const criticidadeCell = document.createElement('td');  // Cria uma célula para o nível de criticidade
        criticidadeCell.textContent = getCriticidadeLevel(item.points); // Exibe a criticidade (BAIXO, MÉDIO, ALTO)
        listItem.appendChild(criticidadeCell);

        listElement.appendChild(listItem);
    });
}
