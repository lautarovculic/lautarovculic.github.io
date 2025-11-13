(function () {
  const render = () => {
    const path = location.pathname.replace(/index\.html$/, '');
    if (!path.endsWith('/writeups/') && !path.endsWith('/writeups')) return;

    const data = document.querySelectorAll('#writeups-data .wu');
    const tagsBox = document.querySelector('#tags-container');
    const listBox = document.querySelector('#filtered-writeups');
    if (!data.length || !tagsBox || !listBox) return;

    const writeups = [];
    const counts = new Map();
    data.forEach(e => {
      const t = e.dataset.title;
      const u = e.dataset.url;
      const tags = (e.dataset.tags || '').split('|').map(s => s.trim().toLowerCase()).filter(Boolean);
      if (!t || !u) return;
      writeups.push({ title: t, href: u, tags });
      for (const x of tags) counts.set(x, (counts.get(x) || 0) + 1);
    });

    const items = [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([t, c]) =>
        `<a href="javascript:void(0)" class="custom-tag" data-tag="${t}">
           <span class="tag-name">#${t}</span>
           <span class="tag-count">${c}</span>
         </a>`
      ).join('');
    tagsBox.innerHTML = `<div class="custom-tags-cloud">${items}</div>`;

    let active = null;

    function renderList(tag) {
      const f = writeups.filter(w => w.tags.includes(tag));
      listBox.innerHTML = f.length
        ? `<div class="filtered-writeups-list">
             <h3>Writeups tagged with #${tag}</h3>
             <ul>${f.map(w => `
                 <li>
                   <a href="${w.href}">${w.title}</a>
                   <span class="writeup-tags">
                     ${w.tags.map(x => `<span class="mini-tag">#${x}</span>`).join(' ')}
                   </span>
                 </li>`).join('')}
             </ul>
           </div>`
        : `<p class="no-results">No writeups found with this tag.</p>`;
    }

    function clear() {
    active = null;
    listBox.innerHTML = '';
    document.querySelectorAll('.custom-tag').forEach(x => x.classList.remove('active'));
    
    history.replaceState(null, '', location.pathname);
    }

    function apply(tag) {
    const wasActive = (active === tag);

    active = tag;
    document.querySelectorAll('.custom-tag').forEach(x =>
        x.classList.toggle('active', x.dataset.tag === tag)
    );
    
    renderList(tag);

    history.replaceState(null, '', `#${tag}`);
    }


    tagsBox.addEventListener('click', (e) => {
      const el = e.target.closest('.custom-tag');
      if (!el) return;
      e.preventDefault();
      const tag = el.dataset.tag;
      (active === tag) ? clear() : apply(tag);
    });

    // 💥 Deep-link al cargar
    const hash = decodeURIComponent(location.hash || '').replace(/^#/, '').toLowerCase();
    if (hash && counts.has(hash)) apply(hash);
  };

  if (window.document$) document$.subscribe(render);
  else document.addEventListener('DOMContentLoaded', render);
})();

(function () {
  function renderPageTags() {
    const path = location.pathname.replace(/index\.html$/, '');
    if (!/\/writeups\/.+/.test(path) || /\/writeups\/?$/.test(path)) return;

    const holder = document.getElementById('page-tags-data');
    if (!holder) return;

    const tags = (holder.dataset.tags || '')
      .split('|').map(t => t.trim()).filter(Boolean);
    if (!tags.length) return;

    const h1 = document.querySelector('.md-content__inner h1');
    if (!h1) return;

    const bar = document.createElement('div');
    bar.className = 'page-tags';
    bar.innerHTML = tags.map(t =>
      `<a class="mini-tag-link" href="/writeups/#${encodeURIComponent(t)}">#${t}</a>`
    ).join(' ');

    h1.insertAdjacentElement('beforebegin', bar);
  }

  if (window.document$) document$.subscribe(renderPageTags);
  else document.addEventListener('DOMContentLoaded', renderPageTags);
})();
