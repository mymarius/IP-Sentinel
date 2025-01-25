document.addEventListener('DOMContentLoaded', () => {
    const ipForm = document.getElementById('ipForm');
    const resultContainer = document.getElementById('resultContainer');

    class IPRiskAnalyzer {
        constructor() {
            this.riskFactors = {
                blacklistedCountries: ['RU', 'CN', 'IR', 'KP', 'SY', 'IQ', 'VN', 'BY'],
                riskyCIDRs: [
                    '5.188.0.0/16', '45.144.0.0/14', 
                    '85.113.0.0/16', '185.153.196.0/22',
                    '192.168.0.0/16', '10.0.0.0/8'
                ],
                suspiciousISPs: [
                    'Tor', 'VPN', 'Proxy', 'Hosting', 
                    'Cloud Provider', 'Anonymizer', 'Anonymous'
                ]
            };
        }

        analyzeIPRisk(data) {
            let riskScore = 0;
            const analysis = {
                totalRiskScore: 0,
                riskDetails: {},
                recommendations: [],
                securityInsights: []
            };

            // Country Risk Assessment
            if (this.riskFactors.blacklistedCountries.includes(data.country_code || data.countryCode)) {
                riskScore += 40;
                analysis.riskDetails.countryRisk = {
                    status: 'High Risk',
                    explanation: 'IP address belongs to a high-risk country'
                };
                analysis.recommendations.push('Avoid using VPNs or proxies');
            }

            // Network Range Risk
            const checkIPRange = (ip, ranges) => {
                return ranges.some(range => {
                    const [network, cidrMask] = range.split('/');
                    return ip.startsWith(network.split('.').slice(0, parseInt(cidrMask)).join('.'));
                });
            };

            if (checkIPRange(data.ip, this.riskFactors.riskyCIDRs)) {
                riskScore += 30;
                analysis.riskDetails.networkRisk = {
                    status: 'Potentially Dangerous Network',
                    explanation: 'IP address belongs to a suspicious network range'
                };
                analysis.recommendations.push('Take additional network security measures');
            }

            // ISP/Organization Risk
            const org = (data.org || data.isp || '').toLowerCase();
            if (this.riskFactors.suspiciousISPs.some(isp => org.includes(isp.toLowerCase()))) {
                riskScore += 20;
                analysis.riskDetails.ispRisk = {
                    status: 'Anonymity Risk',
                    explanation: 'IP address is using an anonymization/masking service'
                };
                analysis.recommendations.push('Use your real IP address');
            }

            // Geographical Anomaly Risk
            if ((data.latitude && data.longitude) && 
                (Math.abs(parseFloat(data.latitude)) > 60 || Math.abs(parseFloat(data.longitude)) > 150)) {
                riskScore += 10;
                analysis.riskDetails.geoRisk = {
                    status: 'Geographical Anomaly',
                    explanation: 'IP location is in an unexpected region'
                };
                analysis.securityInsights.push('Geographical location appears suspicious');
            }

            // Advanced Threat Detection
            if (data.asn && parseInt(data.asn) < 1000) {
                riskScore += 15;
                analysis.riskDetails.asnRisk = {
                    status: 'Potential Threat Source',
                    explanation: 'Low ASN number may indicate suspicious activity'
                };
            }

            analysis.totalRiskScore = Math.min(riskScore, 100);
            analysis.riskLevel = 
                analysis.totalRiskScore < 30 ? 'Low Risk' :
                analysis.totalRiskScore < 60 ? 'Medium Risk' : 'High Risk';

            return analysis;
        }
    }

    class IPInfoFetcher {
        constructor() {
            this.apiUrls = [
                'https://ipapi.co/${ip}/json/',
                'https://ipinfo.io/${ip}/json',
                'https://ip-api.com/json/${ip}'
            ];
        }

        async fetchIPInfo(ip) {
            for (const apiUrlTemplate of this.apiUrls) {
                const apiUrl = apiUrlTemplate.replace('${ip}', ip);
                try {
                    const response = await fetch(apiUrl, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json' }
                    });
                    
                    if (!response.ok) continue;
                    
                    const data = await response.json();
                    if (data.error) continue;
                    
                    return data;
                } catch (error) {
                    console.error(`Error fetching from ${apiUrl}:`, error);
                }
            }
            
            throw new Error('All APIs failed');
        }
    }

    function displayIPInfo(data) {
        const analyzer = new IPRiskAnalyzer();
        const riskAnalysis = analyzer.analyzeIPRisk(data);
        
        const riskLevelClass = 
            riskAnalysis.totalRiskScore < 30 ? 'low-risk' :
            riskAnalysis.totalRiskScore < 60 ? 'medium-risk' : 'high-risk';
    
        resultContainer.innerHTML = `
            <div class="info">
                <p><i class="fas fa-map-pin"></i><strong>IP Address:</strong> ${escapeHtml(data.ip || data.query)}</p>
                <p><i class="fas fa-flag"></i><strong>Country:</strong> ${escapeHtml(data.country_name || data.country)}</p>
                <p><i class="fas fa-map-marker-alt"></i><strong>Region:</strong> ${escapeHtml(data.region || data.region_name)}</p>
                <p><i class="fas fa-building"></i><strong>City:</strong> ${escapeHtml(data.city)}</p>
                <p><i class="fas fa-network-wired"></i><strong>ISP:</strong> ${escapeHtml(data.org || data.isp)}</p>
            </div>
            <div class="risk-analysis ${riskLevelClass}">
                <h3>
                    <i class="fas ${riskLevelClass === 'low-risk' ? 'fa-shield' : 
                        riskLevelClass === 'medium-risk' ? 'fa-exclamation-triangle' : 'fa-skull-crossbones'}"></i>
                    Security Risk Analysis
                </h3>
                <div class="risk-score">Risk Score: ${riskAnalysis.totalRiskScore}/100</div>
                <p><strong>Risk Level:</strong> ${riskAnalysis.riskLevel}</p>
                ${Object.entries(riskAnalysis.riskDetails).map(([key, detail]) => `
                    <p><strong>${detail.status}:</strong> ${detail.explanation}</p>
                `).join('')}
                ${riskAnalysis.recommendations.length ? `
                    <div class="recommendations">
                        <h4>Recommendations:</h4>
                        ${riskAnalysis.recommendations.map(rec => `<p>• ${rec}</p>`).join('')}
                    </div>
                ` : ''}
                ${riskAnalysis.securityInsights.length ? `
                    <div class="security-insights">
                        <h4>Security Insights:</h4>
                        ${riskAnalysis.securityInsights.map(insight => `<p>• ${insight}</p>`).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }

    function displayError(message) {
        resultContainer.innerHTML = `
            <p class="error">${escapeHtml(message)}</p>
        `;
    }

    function escapeHtml(unsafe) {
        return unsafe
            ? unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;")
            : 'No Information';
    }

    ipForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const ipInput = document.getElementById('ipInput');
        const ip = ipInput.value.trim();
        
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            displayError('Invalid IP address. Please enter a valid IP address.');
            return;
        }

        try {
            const ipFetcher = new IPInfoFetcher();
            const response = await ipFetcher.fetchIPInfo(ip);
            
            if (response && response.ip) {
                displayIPInfo(response);
            } else {
                displayError('Could not retrieve IP information. Please enter a valid IP address.');
            }
        } catch (error) {
            displayError(`An error occurred: ${error.message}`);
        }
    });
});
