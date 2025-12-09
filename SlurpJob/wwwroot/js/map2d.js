window.slurpMap2D = {
    instance: null,
    canvas: null,
    ctx: null,
    countryData: {},
    countries: null,
    projection: null,
    animating: false,

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

    init: function (elementId) {
        this.canvas = document.getElementById(elementId);
        if (!this.canvas) {
            console.error('2D Map canvas not found');
            return;
        }

        this.ctx = this.canvas.getContext('2d');
        this.resize();

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

    animate: function () {
        if (!this.ctx) return;

        this.draw();
        if (this.animating) {
            requestAnimationFrame(() => this.animate());
        }
    },

    draw: function () {
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;

        // Clear with black background
        ctx.fillStyle = '#000000';
        ctx.fillRect(0, 0, w, h);

        // Draw countries if loaded
        if (this.countries && this.projection) {
            this.countries.forEach(feature => {
                // Handle different property naming conventions
                const props = feature.properties || {};

                // Try to get ISO2 code directly first (attack data uses ISO2)
                let iso2 = props.ISO_A2 || props.iso_a2;

                // If not found, try converting from ISO3
                if (!iso2) {
                    const iso3 = props.ISO_A3 || props.ISO3 || props.iso_a3 || props.ADM0_A3;
                    iso2 = iso3 ? Object.keys(this.iso2to3).find(key => this.iso2to3[key] === iso3) : null;
                }

                const count = iso2 ? (this.countryData[iso2] || 0) : 0;

                // Get color for country
                const color = this.getHeatColor(count);

                // Draw country polygon
                this.drawCountry(feature.geometry, color);
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
    },

    drawCountry: function (geometry, fillColor) {
        const ctx = this.ctx;

        if (!geometry || !this.projection) return;

        ctx.fillStyle = fillColor;
        ctx.strokeStyle = '#222';
        ctx.lineWidth = 0.5;

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
            ctx.stroke();
        };

        if (geometry.type === 'Polygon') {
            geometry.coordinates.forEach(ring => drawPolygon(ring));
        } else if (geometry.type === 'MultiPolygon') {
            geometry.coordinates.forEach(polygon => {
                polygon.forEach(ring => drawPolygon(ring));
            });
        }
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

    dispose: function () {
        this.animating = false;
        this.instance = null;
        this.canvas = null;
        this.ctx = null;
        this.countries = null;
    }
};
