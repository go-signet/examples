<script setup lang="ts">
import { useAuth } from './auth/useAuth'

const { isAuthenticated } = useAuth()
</script>

<template>
  <header>
    <nav>
      <strong>Signet Vue SPA</strong>
      <router-link to="/">Home</router-link>
      <router-link v-if="isAuthenticated" to="/profile">Profile</router-link>
    </nav>
  </header>
  <main>
    <router-view />
  </main>
</template>

<style>
:root {
  color-scheme: light dark;
  font-family: system-ui, -apple-system, sans-serif;
  line-height: 1.5;
}

body {
  margin: 0;
}

header nav {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem 1.5rem;
  border-bottom: 1px solid color-mix(in srgb, currentColor 20%, transparent);
}

main {
  max-width: 48rem;
  margin: 0 auto;
  padding: 1.5rem;
}

button {
  font: inherit;
  padding: 0.4rem 0.9rem;
  cursor: pointer;
}

pre {
  padding: 0.75rem;
  overflow-x: auto;
  background: color-mix(in srgb, currentColor 8%, transparent);
  border-radius: 4px;
}

.error {
  padding: 0.75rem;
  border: 1px solid #c0392b;
  border-radius: 4px;
  color: #c0392b;
}

.warning {
  padding: 0.75rem;
  border: 1px solid #b7791f;
  border-radius: 4px;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin: 1rem 0;
}
</style>
