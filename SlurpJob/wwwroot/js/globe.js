window.slurpGlobe = {
    instance: null,
    countryData: {},

    // ISO Alpha-2 to Alpha-3 country code mapping (subset - add more as needed)
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
        const element = document.getElementById(elementId);
        if (!element) return;

        if (typeof Globe === 'undefined') {
            console.error("Globe.gl library not loaded");
            return;
        }

        this.instance = Globe()
            .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
            .backgroundColor('#000000')
            .showAtmosphere(true)
            .atmosphereColor('#00ffff')
            .atmosphereAltitude(0.15)
            (element);

        this.instance.controls().autoRotate = true;
        this.instance.controls().autoRotateSpeed = 0.6;

        // Load country polygons
        fetch('//unpkg.com/world-atlas/countries-110m.json')
            .then(res => res.json())
            .then(countries => {
                this.instance
                    .polygonsData(countries.features)
                    .polygonCapColor(feat => this.getCountryColor(feat.properties.ISO_A3))
                    .polygonSideColor(() => 'rgba(0, 0, 0, 0.1)')
                    .polygonStrokeColor(() => '#111')
                    .polygonAltitude(0.01);
            });
    },

    getCountryColor: function (iso3) {
        // Find matching country code (convert ISO3 to ISO2)
        const iso2 = Object.keys(this.iso2to3).find(key => this.iso2to3[key] === iso3);
        const count = iso2 ? (this.countryData[iso2] || 0) : 0;

        // Heatmap gradient
        if (count === 0) return 'rgba(30, 58, 138, 0.4)'; // dark blue
        if (count < 5) return 'rgba(59, 130, 246, 0.6)'; // blue
        if (count < 20) return 'rgba(6, 182, 212, 0.7)'; // cyan
        if (count < 50) return 'rgba(234, 179, 8, 0.8)'; // yellow
        if (count < 100) return 'rgba(249, 115, 22, 0.9)'; // orange
        return 'rgba(239, 68, 68, 0.95)'; // red
    },

    updateHeatmap: function (countryData) {
        this.countryData = countryData || {};

        // Refresh polygon colors
        if (this.instance && this.instance.polygonsData()) {
            this.instance.polygonCapColor(this.instance.polygonCapColor());
        }
    },

    dispose: function () {
        if (this.instance) {
            // Globe.gl doesn't have a built-in dispose, but we can clear the data
            this.instance.polygonsData([]);
        }
        this.instance = null;
    }
};
