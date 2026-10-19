/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // HIPAA-adjacent defaults: no PHI in error payloads sent to the browser.
  productionBrowserSourceMaps: false,
};

export default nextConfig;
