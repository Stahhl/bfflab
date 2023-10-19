<script lang="ts">
  import svelteLogo from "./assets/svelte.svg";
  import viteLogo from "/vite.svg";
  import Counter from "./lib/Counter.svelte";
  import { onMount } from "svelte";

  let user = {};
  let isAuthenticated = false;

  onMount(async () => {
    const res = await fetch(`http://localhost:5204/user`);
    if (res.ok) {
      isAuthenticated = true;
      user = await res.json();
      console.log(user);
    }
  });
</script>

<main>

  <div>
    <h1>Logged in? {isAuthenticated}</h1>
    <a
      class="btn btn-secondary m-1"
      role="button"
      href="http://localhost:5204/login?origin=http://localhost:5173">Login</a
    >
  </div>
  
</main>
