import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  getProjects as apiGetProjects,
  createProject as apiCreateProject,
  deleteProject as apiDeleteProject,
  getSessions,
  createSession as apiCreateSession,
  deleteSession as apiDeleteSession,
} from '../api';

const AppContext = createContext(null);

export function AppProvider({ children }) {
  // Project state
  const [projects, setProjects] = useState([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [projectsError, setProjectsError] = useState(null);

  // Session state (kept for backwards compat)
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // ── Projects ──────────────────────────────────────────────────────────────

  const fetchProjects = useCallback(async () => {
    try {
      setProjectsLoading(true);
      const data = await apiGetProjects();
      setProjects(Array.isArray(data) ? data : []);
      setProjectsError(null);
    } catch (err) {
      setProjectsError(err.message);
    } finally {
      setProjectsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProjects();
  }, [fetchProjects]);

  const createProject = useCallback(async (data) => {
    const project = await apiCreateProject(data);
    setProjects((prev) => [...prev, project]);
    return project;
  }, []);

  const removeProject = useCallback(async (id) => {
    await apiDeleteProject(id);
    setProjects((prev) => prev.filter((p) => p.id !== id));
  }, []);

  // ── Sessions ──────────────────────────────────────────────────────────────

  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getSessions();
      setSessions(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  const createSession = useCallback(async (projectId, name, target, profileId) => {
    const session = await apiCreateSession(projectId, name, target, profileId);
    setSessions((prev) => [...prev, session]);
    return session;
  }, []);

  const removeSession = useCallback(async (id) => {
    await apiDeleteSession(id);
    setSessions((prev) => prev.filter((s) => s.id !== id));
  }, []);

  const value = {
    // Projects
    projects,
    projectsLoading,
    projectsError,
    fetchProjects,
    createProject,
    removeProject,
    // Sessions
    sessions,
    loading,
    error,
    fetchSessions,
    createSession,
    removeSession,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}
