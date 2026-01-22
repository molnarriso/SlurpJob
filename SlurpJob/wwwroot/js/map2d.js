window.slurpMap2D = {
    instance: null,
    canvas: null,
    ctx: null,
    countryData: {},
    countries: null,
    projection: null,
    animating: false,
    hoveredCountry: null,
    mouseX: 0,
    mouseY: 0,
    dotNetRef: null,
    visualState: { activeCountry: null, mode: 'None' }, // { activeCountry: 'FR', mode: 'Exclusive'|'Filtered'|'None' }
    blinkingCountries: {},

    // ISO Alpha-2 to Alpha-3 mapping (same as globe)
    iso2to3: {
        'US': 'USA', 'CN': 'CHN', 'RU': 'RUS', 'GB': 'GBR', 'DE': 'DEU',
        'FR': 'FRA', 'JP': 'JPN', 'KR': 'KOR', 'IN': 'IND', 'BR': 'BRA',
        'AU': 'AUS', 'CA': 'CAN', 'MX': 'MEX', 'AR': 'ARG', 'ZA': 'ZAF',
        'EG': 'EGY', 'NG': 'NGA', 'TR': 'TUR', 'SA': 'SAU', 'ID': 'IDN',
        'PH': 'PHL', 'VN': 'VNM', 'TH': 'THA', 'MY': 'MYS', 'SG': 'SGP',
        'NZ': 'NZL', 'PL': 'POL', 'UA': 'UKR', 'IT': 'ITA', 'ES': 'ESP',
        'SE': 'SWE', 'NO': 'NOR', 'FI': 'FIN', 'NL': 'NLD', 'BE': 'BEL',
        'CH': 'CHE', 'AT': 'AUT', 'CZ': 'CZE', 'PT': 'PRT', 'GR': 'GRC',
        'RO': 'ROU', 'HU': 'HUN', 'IE': 'IRL', 'DK': 'DNK', 'IL': 'ISR',
        'AE': 'ARE'
    },

    init: function (elementId, dotNetRef) {
        this.canvas = document.getElementById(elementId);
        if (!this.canvas) {
            console.error('2D Map canvas not found');
            return;
        }

        this.dotNetRef = dotNetRef;
        this.ctx = this.canvas.getContext('2d');
        this.resize();

        // Add mouse event listeners for interactivity
        this.canvas.addEventListener('mousemove', (e) => this.handleMouseMove(e));
        this.canvas.addEventListener('mouseleave', () => this.handleMouseLeave());
        this.canvas.addEventListener('click', (e) => this.handleClick(e));

        window.addEventListener('resize', () => this.resize());

        // Load country data - using Natural Earth GeoJSON with reliable ISO codes
        fetch('https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson')
            .then(res => res.json())
            .then(geoData => {
                this.countries = geoData.features;
                // Start animation only after data is loaded
                if (!this.animating) {
                    this.animating = true;
                    this.animate();
                }
            })
            .catch(err => {
                console.error('Failed to load country data:', err);
                // Start animation anyway to show grid
                if (!this.animating) {
                    this.animating = true;
                    this.animate();
                }
            });
    },

    resize: function () {
        if (!this.canvas) return;
        this.canvas.width = this.canvas.offsetWidth;
        this.canvas.height = this.canvas.offsetHeight;

        // Simple equirectangular projection
        this.projection = {
            width: this.canvas.width,
            height: this.canvas.height,
            project: (lon, lat) => {
                const x = ((lon + 180) / 360) * this.canvas.width;
                const y = ((90 - lat) / 180) * this.canvas.height;
                return [x, y];
            }
        };
    },

    handleMouseMove: function (e) {
        const rect = this.canvas.getBoundingClientRect();
        this.mouseX = e.clientX - rect.left;
        this.mouseY = e.clientY - rect.top;

        // Find country under cursor
        this.hoveredCountry = null;
        if (this.countries && this.projection) {
            for (const feature of this.countries) {
                if (this.isPointInCountry(this.mouseX, this.mouseY, feature.geometry)) {
                    this.hoveredCountry = feature;
                    this.canvas.style.cursor = 'pointer';
                    return;
                }
            }
        }
        this.canvas.style.cursor = 'default';
    },

    handleMouseLeave: function () {
        this.hoveredCountry = null;
        this.canvas.style.cursor = 'default';
    },

    handleClick: function (e) {
        if (!this.hoveredCountry || !this.dotNetRef) return;

        const iso2 = this.getIsoCode(this.hoveredCountry);
        if (iso2) {
            this.dotNetRef.invokeMethodAsync('OnCountryClicked', iso2);
        }
    },

    isPointInCountry: function (x, y, geometry) {
        if (!geometry || !this.ctx) return false;

        const checkPolygon = (coords) => {
            this.ctx.beginPath();
            let first = true;
            coords.forEach(point => {
                const [lon, lat] = point;
                const [px, py] = this.projection.project(lon, lat);
                if (first) {
                    this.ctx.moveTo(px, py);
                    first = false;
                } else {
                    this.ctx.lineTo(px, py);
                }
            });
            this.ctx.closePath();
            return this.ctx.isPointInPath(x, y);
        };

        if (geometry.type === 'Polygon') {
            for (const ring of geometry.coordinates) {
                if (checkPolygon(ring)) return true;
            }
        } else if (geometry.type === 'MultiPolygon') {
            for (const polygon of geometry.coordinates) {
                for (const ring of polygon) {
                    if (checkPolygon(ring)) return true;
                }
            }
        }
        return false;
    },

    animate: function () {
        if (!this.ctx) return;

        this.draw();
        if (this.animating) {
            requestAnimationFrame(() => this.animate());
        }
    },

    updateVisuals: function (visuals) {
        // visuals = { activeCountry: 'FR', mode: 'Exclusive' }
        if (visuals) {
            this.visualState = visuals;
            // No need to manually redraw, loop will pick it up
        }
    },

    triggerBlink: function (isoCode) {
        if (!isoCode) return;
        this.blinkingCountries[isoCode] = Date.now();
        if (!this.animating) {
            this.animating = true;
            this.animate();
        }
    },

    getIsoCode: function (feature) {
        const props = feature.properties || {};
        let iso2 = props.ISO_A2 || props.iso_a2;
        if (iso2 === "-99" || iso2 === -99) iso2 = null;
        if (!iso2) {
            iso2 = props.ISO_A2_EH || props.iso_a2_eh;
            if (iso2 === "-99" || iso2 === -99) iso2 = null;
        }
        if (!iso2) {
            let iso3 = props.ISO_A3 || props.ISO3 || props.iso_a3;
            if (!iso3 || iso3 === "-99" || iso3 === -99) iso3 = props.ISO_A3_EH || props.iso_a3_eh;
            if (!iso3 || iso3 === "-99" || iso3 === -99) iso3 = props.ADM0_A3;
            if (iso3 && iso3 !== "-99" && iso3 !== -99) iso2 = Object.keys(this.iso2to3).find(key => this.iso2to3[key] === iso3);
        }
        return iso2;
    },

    draw: function () {
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;
        const { activeCountry, mode } = this.visualState;

        // Clear with black background
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, w, h);

        // Draw countries if loaded
        if (this.countries && this.projection) {
            this.countries.forEach(feature => {
                const iso2 = this.getIsoCode(feature);
                const count = iso2 ? (this.countryData[iso2] || 0) : 0;
                let color = this.getHeatColor(count);
                let borderStyle = null;

                // --- Visual State Logic ---
                if (activeCountry && mode !== 'None') {
                    if (iso2 === activeCountry) {
                        // This is the active country
                        if (mode === 'Filtered') {
                            // Filtered out -> Black (Hide) + Red Border
                            color = '#000000';
                            borderStyle = { color: '#ff4444', width: 2 };
                        } else {
                            // Exclusive -> Normal (Highlight?) + Green Border
                            // color = color; // Keep heat map color
                            borderStyle = { color: '#00C851', width: 2 };
                        }
                    } else {
                        // This is OTHER countries
                        if (mode === 'Exclusive') {
                            // Exclusive -> Dim others
                            color = this.dimColor(color, 0.2);
                        } else {
                            // Filtered -> Others are normal
                        }
                    }
                }
                // --------------------------

                // Draw country polygon
                const isHovered = this.hoveredCountry === feature;
                this.drawCountry(feature.geometry, color, isHovered, borderStyle);

                // Draw blink overlay (Explosion Effect)
                if (this.blinkingCountries[iso2]) {
                    const start = this.blinkingCountries[iso2];
                    const elapsed = Date.now() - start;
                    const duration = 1000;
                    if (elapsed < duration) {
                        const progress = elapsed / duration;
                        // Exponential ease-out for better "pop"
                        const ease = 1 - Math.pow(1 - progress, 3);

                        // Width grows significantly
                        const maxLineWidth = 50;
                        const lineWidth = 1 + (maxLineWidth * ease);

                        // Opacity fades out
                        const opacity = 1 - ease;
                        const blinkColor = `rgba(255, 68, 68, ${opacity})`; // Reddish explosion

                        // Draw expanding stroke (transparent fill)
                        // Reuse drawCountry but focusing on the stroke
                        this.drawCountry(feature.geometry, 'transparent', false, { color: blinkColor, width: lineWidth });
                    } else {
                        delete this.blinkingCountries[iso2];
                    }
                }
            });
        }

        // Draw grid lines
        ctx.strokeStyle = '#1a1a1a';
        ctx.lineWidth = 1;

        // Latitude lines
        for (let i = 0; i <= 4; i++) {
            const y = (h / 4) * i;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }

        // Longitude lines
        for (let i = 0; i <= 8; i++) {
            const x = (w / 8) * i;
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }

        // Draw tooltip if hovering over a country
        if (this.hoveredCountry) {
            this.drawTooltip();
        }
    },

    dimColor: function (rgbaString, opacityResult) {
        // Quick regex parse of 'rgba(r, g, b, a)'
        // If it's not rgba, ignore for now (should be consistent though)
        if (rgbaString.startsWith('rgba')) {
            return rgbaString.replace(/, [\d\.]+\)$/, `, ${opacityResult})`);
        }
        return rgbaString;
    },

    drawCountry: function (geometry, fillColor, isHovered, borderStyle, skipStroke = false) {
        const ctx = this.ctx;

        if (!geometry || !this.projection) return;

        ctx.fillStyle = fillColor;

        // Border Styling Hierarchy: Hover > Visual State > Default
        if (isHovered) {
            ctx.strokeStyle = '#0ff';
            ctx.lineWidth = 2;
        } else if (borderStyle) {
            ctx.strokeStyle = borderStyle.color;
            ctx.lineWidth = borderStyle.width;
        } else {
            ctx.strokeStyle = '#222';
            ctx.lineWidth = 0.5;
        }

        const drawPolygon = (coords) => {
            if (coords.length === 0) return;

            ctx.beginPath();
            let first = true;

            coords.forEach(point => {
                const [lon, lat] = point;
                const [x, y] = this.projection.project(lon, lat);

                if (first) {
                    ctx.moveTo(x, y);
                    first = false;
                } else {
                    ctx.lineTo(x, y);
                }
            });

            ctx.closePath();
            ctx.fill();
            if (!skipStroke) ctx.stroke();
        };

        if (geometry.type === 'Polygon') {
            geometry.coordinates.forEach(ring => drawPolygon(ring));
        } else if (geometry.type === 'MultiPolygon') {
            geometry.coordinates.forEach(polygon => {
                polygon.forEach(ring => drawPolygon(ring));
            });
        }
    },

    drawTooltip: function () {
        if (!this.hoveredCountry) return;

        const ctx = this.ctx;
        const props = this.hoveredCountry.properties || {};

        // Get country name and code
        const name = props.NAME || props.name || props.ADMIN || 'Unknown';
        const iso2 = this.getIsoCode(this.hoveredCountry);
        const count = iso2 ? (this.countryData[iso2] || 0) : 0;

        // Format tooltip text
        const line1 = name;
        const line2 = `Attacks: ${count}`;

        // Measure text
        ctx.font = 'bold 14px Arial';
        const width1 = ctx.measureText(line1).width;
        ctx.font = '12px Arial';
        const width2 = ctx.measureText(line2).width;
        const maxWidth = Math.max(width1, width2);

        // Tooltip dimensions
        const padding = 8;
        const tooltipWidth = maxWidth + padding * 2;
        const tooltipHeight = 50;

        // Position tooltip near cursor
        let x = this.mouseX + 15;
        let y = this.mouseY - 10;

        // Keep tooltip in bounds
        if (x + tooltipWidth > this.canvas.width) x = this.mouseX - tooltipWidth - 15;
        if (y + tooltipHeight > this.canvas.height) y = this.canvas.height - tooltipHeight;
        if (y < 0) y = 0;

        // Draw tooltip background
        ctx.fillStyle = 'rgba(0, 0, 0, 0.85)';
        ctx.fillRect(x, y, tooltipWidth, tooltipHeight);

        // Draw border
        ctx.strokeStyle = '#0ff';
        ctx.lineWidth = 1;
        ctx.strokeRect(x, y, tooltipWidth, tooltipHeight);

        // Draw text
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 14px Arial';
        ctx.fillText(line1, x + padding, y + 20);

        ctx.font = '12px Arial';
        ctx.fillStyle = '#fff';  // Always white for readability
        ctx.fillText(line2, x + padding, y + 38);
    },

    getHeatColor: function (count) {
        // Same gradient as globe
        if (count === 0) return 'rgba(30, 58, 138, 0.4)'; // dark blue
        if (count < 5) return 'rgba(59, 130, 246, 0.6)'; // blue
        if (count < 20) return 'rgba(6, 182, 212, 0.7)'; // cyan
        if (count < 50) return 'rgba(234, 179, 8, 0.8)'; // yellow
        if (count < 100) return 'rgba(249, 115, 22, 0.9)'; // orange
        return 'rgba(239, 68, 68, 0.95)'; // red
    },

    updateHeatmap: function (countryData) {
        this.countryData = countryData || {};
    },

    updateVisuals: function (visuals) {
        if (visuals) {
            this.visualState = visuals; // { activeCountry, mode }
        }
    },

    dispose: function () {
        this.animating = false;
        this.instance = null;
        this.canvas = null;
        this.ctx = null;
        this.countries = null;
    }
};
