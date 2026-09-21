import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import AppSidebar from './AppSidebar';

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-gray-950">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      <main
        className="min-h-screen transition-all duration-300 ease-in-out"
        style={{ marginLeft: collapsed ? 68 : 220 }}
      >
        <Outlet />
      </main>
    </div>
  );
}
