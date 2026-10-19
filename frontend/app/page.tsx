/**
 * M1a placeholder. This page exists so the frontend has a real entry point to build on;
 * it is NOT the product. No case, criteria, letter or patient data is rendered here.
 */
export default function Home() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <h1 className="text-3xl font-semibold text-brand">CardioAuth</h1>
      <p className="mt-4 text-lg">
        Prior-authorization and appeal assistant for independent cardiology practices.
      </p>
      <div className="mt-8 rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">
        <strong>M1a foundation.</strong> The schema, migrations and audit chain exist; the
        coordinator workflow (upload → checklist → gap report → letter → sign-off) is not
        built yet. The criteria library is unverified placeholder data — not for real
        patient use.
      </div>
    </main>
  );
}
