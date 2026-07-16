(function() {
  const ipInput = document.getElementById('ipInput');
  const cidrSlider = document.getElementById('cidrSlider');
  const cidrDisplay = document.getElementById('cidrDisplay');
  const supernetSelect = document.getElementById('supernetSelect');
  const calculateBtn = document.getElementById('calculateBtn');
  const resultsContainer = document.getElementById('resultsContainer');

  // Utility functions for IP calculations
  function ipToOctets(ipStr) {
    const trimmed = ipStr.trim();
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return null;
    const parts = trimmed.split('.').map(Number);
    if (parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    return parts;
  }

  function octetsToInt(octets) {
    return ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  }

  function intToOctets(intVal) {
    return [
      (intVal >>> 24) & 255,
      (intVal >>> 16) & 255,
      (intVal >>> 8) & 255,
      intVal & 255
    ];
  }

  function ipToString(octets) {
    return octets.join('.');
  }

  function getMaskFromCidr(cidr) {
    if (cidr < 0 || cidr > 32) return null;
    if (cidr === 0) return [0, 0, 0, 0];
    const maskInt = (~((1 << (32 - cidr)) - 1)) >>> 0;
    return intToOctets(maskInt);
  }

  function getWildcard(maskOctets) {
    return maskOctets.map(o => 255 - o);
  }

  function getNetworkAddress(ipOctets, cidr) {
    const maskInt = octetsToInt(getMaskFromCidr(cidr));
    const ipInt = octetsToInt(ipOctets);
    return intToOctets((ipInt & maskInt) >>> 0);
  }

  function getBroadcastAddress(netOctets, cidr) {
    const maskInt = octetsToInt(getMaskFromCidr(cidr));
    const netInt = octetsToInt(netOctets);
    const wildcardInt = (~maskInt) >>> 0;
    return intToOctets((netInt | wildcardInt) >>> 0);
  }

  function getHostRange(netOctets, broadcastOctets) {
    const first = [...netOctets];
    first[3] += 1;
    for (let i = 3; i >= 0; i--) {
      if (first[i] > 255) {
        first[i] = 0;
        if (i > 0) first[i-1]++;
      }
    }
    const last = [...broadcastOctets];
    last[3] -= 1;
    for (let i = 3; i >= 0; i--) {
      if (last[i] < 0) {
        last[i] = 255;
        if (i > 0) last[i-1]--;
      }
    }
    return { first, last };
  }

  function getIPClass(octets) {
    const first = octets[0];
    if (first >= 1 && first <= 126) return 'A';
    if (first === 127) return 'Loopback';
    if (first >= 128 && first <= 191) return 'B';
    if (first >= 192 && first <= 223) return 'C';
    if (first >= 224 && first <= 239) return 'D (Multicast)';
    if (first >= 240 && first <= 255) return 'E (Reserved)';
    return 'Unknown';
  }

  function getDefaultCidrByClass(octets) {
    const cls = getIPClass(octets);
    if (cls === 'A') return 8;
    if (cls === 'B') return 16;
    if (cls === 'C') return 24;
    return null;
  }

  function formatBinaryOctets(octets, cidr) {
    return octets.map((o, idx) => {
      let bin = o.toString(2).padStart(8, '0');
      const bitStart = idx * 8;
      let styled = '';
      for (let i = 0; i < 8; i++) {
        const globalBit = bitStart + i;
        if (globalBit < cidr) {
          styled += `<span class="network-bit">${bin[i]}</span>`;
        } else {
          styled += `<span class="host-bit">${bin[i]}</span>`;
        }
      }
      return styled;
    }).join('.');
  }

  function getSupernetDescription(ipOctets, cidr) {
    const classDefault = getDefaultCidrByClass(ipOctets);
    if (classDefault !== null && cidr < classDefault) {
      return 'Supernet (aggregated)';
    } else if (classDefault !== null && cidr > classDefault) {
      return 'Subnet (divided)';
    } else if (classDefault !== null && cidr === classDefault) {
      return 'Classful network';
    }
    return 'CIDR allocation';
  }

  function renderResults(ipOctets, cidr) {
    if (!ipOctets || cidr === undefined || cidr === null || cidr < 0 || cidr > 32) {
      resultsContainer.innerHTML = `
        <div class="card error-message" style="grid-column:1/-1;">
          ⚠️ Invalid IP address or CIDR prefix. Please use format: 0.0.0.0–255.255.255.255 and CIDR 0–32.
        </div>`;
      return;
    }

    const maskOctets = getMaskFromCidr(cidr);
    const wildOctets = getWildcard(maskOctets);
    const netOctets = getNetworkAddress(ipOctets, cidr);
    const broadcastOctets = getBroadcastAddress(netOctets, cidr);
    const range = getHostRange(netOctets, broadcastOctets);
    const totalAddresses = Math.pow(2, 32 - cidr);
    const usableHosts = (cidr >= 31) ? (cidr === 32 ? 0 : 0) : (totalAddresses - 2);
    const ipClass = getIPClass(ipOctets);
    const defaultCidr = getDefaultCidrByClass(ipOctets);
    const supernetDesc = getSupernetDescription(ipOctets, cidr);
    const networkBits = cidr;
    const hostBits = 32 - cidr;

    const ipBin = formatBinaryOctets(ipOctets, cidr);
    const maskBin = formatBinaryOctets(maskOctets, cidr);
    const netBin = formatBinaryOctets(netOctets, cidr);
    const broadcastBin = formatBinaryOctets(broadcastOctets, cidr);

    const html = `
      <!-- Top Row: Main IP Information -->
      <div class="main-info-row">
        <div class="card primary">
          <div class="card-header">
            <span class="icon">📌</span>
            <h3>IP Address Details</h3>
          </div>
          <div class="ip-display">
            ${ipToString(ipOctets)}
            <span class="class-badge">Class ${ipClass}</span>
          </div>
          <div class="binary-display">${ipBin}</div>
          <div style="margin-top: 0.8rem;">
            <span class="highlight">/${cidr} prefix</span>
            <span style="color: #8b949e; margin-left: 0.5rem;">· ${supernetDesc}</span>
          </div>
          <div class="legend">
            <div class="legend-item">
              <span class="legend-dot network"></span> Network bits
            </div>
            <div class="legend-item">
              <span class="legend-dot host"></span> Host bits
            </div>
          </div>
        </div>

        <div class="card secondary">
          <div class="card-header">
            <span class="icon">🧩</span>
            <h3>Network Structure</h3>
          </div>
          <div class="info-row">
            <span class="label">🔹 Network bits</span>
            <strong>${networkBits} bits</strong>
          </div>
          <div class="info-row">
            <span class="label">🔸 Host bits</span>
            <strong>${hostBits} bits</strong>
          </div>
          <div class="info-row">
            <span class="label">📋 Default class mask</span>
            <strong>${defaultCidr ? '/' + defaultCidr : 'N/A'}</strong>
          </div>
          <div class="info-row">
            <span class="label">🏷️ IP Class</span>
            <strong>${ipClass}</strong>
          </div>
          <div style="margin-top: 0.8rem;">
            <span class="status-tag">
              📐 ${supernetDesc} ${defaultCidr ? '(default /' + defaultCidr + ')' : ''}
            </span>
          </div>
        </div>
      </div>

      <!-- Middle Row: Network Addresses -->
      <div class="address-details-row">
        <div class="card accent">
          <div class="card-header">
            <span class="icon">🌐</span>
            <h3>Network Address</h3>
          </div>
          <div class="ip-display" style="font-size: 1.2rem;">${ipToString(netOctets)}</div>
          <div class="binary-display">${netBin}</div>
        </div>

        <div class="card accent">
          <div class="card-header">
            <span class="icon">📢</span>
            <h3>Broadcast Address</h3>
          </div>
          <div class="ip-display" style="font-size: 1.2rem;">${ipToString(broadcastOctets)}</div>
          <div class="binary-display">${broadcastBin}</div>
        </div>

        <div class="card">
          <div class="card-header">
            <span class="icon">🛡️</span>
            <h3>Subnet Mask</h3>
          </div>
          <div class="ip-display" style="font-size: 1.2rem;">${ipToString(maskOctets)}</div>
          <div class="binary-display">${maskBin}</div>
          <div style="color:#8b949e; margin-top:0.5rem; font-size:0.85rem;">
            Wildcard: ${ipToString(wildOctets)}
          </div>
        </div>
      </div>

      <!-- Bottom Row: Host Range & Summary -->
      <div class="summary-row">
        <div class="card primary">
          <div class="card-header">
            <span class="icon">🖥️</span>
            <h3>Usable Host Range</h3>
          </div>
          <div class="range-display">
            <span class="range-item">${ipToString(range.first)}</span>
            <span class="arrow">→</span>
            <span class="range-item">${ipToString(range.last)}</span>
          </div>
          <div style="margin-top: 0.8rem; color: #8b949e; font-size: 0.9rem;">
            Usable hosts: <strong style="color:#2dba4e; font-size:1.1rem;">${usableHosts.toLocaleString()}</strong>
          </div>
        </div>

        <div class="card secondary">
          <div class="card-header">
            <span class="icon">📊</span>
            <h3>Address Summary</h3>
          </div>
          <div class="info-row">
            <span class="label">📦 Total addresses</span>
            <strong>${totalAddresses.toLocaleString()}</strong>
          </div>
          <div class="info-row">
            <span class="label">✅ Usable hosts</span>
            <strong>${usableHosts.toLocaleString()}</strong>
          </div>
          <div class="info-row">
            <span class="label">📐 CIDR notation</span>
            <strong>/${cidr}</strong>
          </div>
          <div class="info-row">
            <span class="label">🏷️ Address class</span>
            <strong>${ipClass}</strong>
          </div>
        </div>
      </div>
    `;

    resultsContainer.innerHTML = html;
  }

  function updateCalculation() {
    const octets = ipToOctets(ipInput.value);
    const cidr = parseInt(cidrSlider.value, 10);
    cidrDisplay.textContent = `/${cidr}`;
    
    if (!octets) {
      resultsContainer.innerHTML = `
        <div class="card error-message" style="grid-column:1/-1;">
          ⚠️ Please enter a valid IPv4 address (e.g. 192.168.1.1)
        </div>`;
      return;
    }
    renderResults(octets, cidr);
  }

  // Event listeners
  calculateBtn.addEventListener('click', updateCalculation);

  cidrSlider.addEventListener('input', function(e) {
    cidrDisplay.textContent = `/${e.target.value}`;
  });
  
  cidrSlider.addEventListener('change', updateCalculation);

  ipInput.addEventListener('input', function() {
    const octets = ipToOctets(ipInput.value);
    if (octets) {
      updateCalculation();
    }
  });

  ipInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') updateCalculation();
  });

  supernetSelect.addEventListener('change', function(e) {
    if (e.target.value !== '') {
      cidrSlider.value = parseInt(e.target.value, 10);
      cidrDisplay.textContent = `/${e.target.value}`;
      updateCalculation();
    }
  });

  // Initial render
  updateCalculation();
})();