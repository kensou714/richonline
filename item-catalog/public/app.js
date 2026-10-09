(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const text = (label, key, column = '') => ({ label, key, column });
  const picture = (label = '图片', map = false) => ({ label, key: 'image', column: map ? 'map-image-column' : 'image-column', type: map ? 'map-image' : 'image' });
  const id = text('ID', 'id', 'id-column');
  const name = text('名字', 'name', 'name-column');
  const description = text('描述', 'description');
  const pages = {
    cards: { label: '道具卡', columns: [id, picture('卡片图'), name, description, text('商店售价', 'price', 'price-column')] },
    events: { label: '事件', columns: [text('资料编号', 'id', 'kind-column'), picture('事件图'), text('类别', 'kind', 'kind-column'), text('名字／适用地图', 'eventName', 'name-column'), description] },
    roles: { label: '角色', columns: [id, picture('角色图'), name, text('性别', 'sex', 'short-column'), text('生日', 'birthday', 'short-column'), text('口头禅', 'description')] },
    npcs: { label: 'NPC', columns: [id, picture('NPC 图'), name, text('出现玩法', 'modes'), text('附身天数', 'affix', 'short-column'), text('重生天数', 'respawn', 'short-column')] },
    maps: { label: '地图', columns: [text('地图编号', 'id', 'map-id-column'), picture('地图预览', true), name, description, text('地块尺寸', 'size', 'short-column')] },
    mall: { label: '商城道具', columns: [id, picture('道具图'), name, text('类别', 'kind', 'short-column'), description, text('商城售价', 'price', 'price-column')] },
    sounds: { label: '音效', columns: [id, name, text('资源文件', 'file', 'file-column'), text('格式', 'format', 'short-column'), text('大小', 'size', 'short-column'), { label: '试听', key: 'audio', column: 'audio-column', type: 'audio' }] },
    music: { label: '背景音乐', columns: [id, name, text('资源文件', 'file', 'file-column'), text('格式', 'format', 'short-column'), text('大小', 'size', 'short-column'), { label: '试听', key: 'audio', column: 'audio-column', type: 'audio' }] },
  };
  const data = window.GAME_CATALOG;
  const pageSize = 100;
  let active = 'cards';
  let pageIndex = 0;
  const element = (tag, content) => {
    const node = document.createElement(tag);
    if (content !== undefined) node.textContent = content;
    return node;
  };
  function stopAudio() {
    document.querySelectorAll('audio').forEach((audio) => {
      audio.pause();
      audio.removeAttribute('src');
      audio.load();
    });
  }
  function imageCell(cell, row, map) {
    cell.className = map ? 'image-cell map-image-cell' : 'image-cell';
    const missing = (message = '暂无图片') => {
      const label = element('span', message);
      label.className = 'missing-image';
      cell.replaceChildren(label);
    };
    if (!row.image) {
      missing(active === 'cards' ? '暂无卡片图' : '暂无图片');
      return;
    }
    const image = element('img');
    image.src = row.image;
    image.alt = `${row.nameSimplified || row.name || row.kind}图片`;
    image.loading = 'lazy';
    image.decoding = 'async';
    image.addEventListener('error', () => missing('图片未能加载'), { once: true });
    cell.append(image);
  }
  function audioCell(cell, row) {
    cell.className = 'audio-cell';
    const audio = element('audio');
    audio.controls = true;
    audio.preload = 'none';
    audio.src = row.audio;
    audio.setAttribute('aria-label', `试听${row.name}`);
    audio.addEventListener('play', () => {
      document.querySelectorAll('audio').forEach((other) => { if (other !== audio) other.pause(); });
    });
    audio.addEventListener('error', () => {
      const message = element('span', '无法试听，');
      message.className = 'audio-error';
      const download = element('a', '下载音频');
      download.href = row.audio;
      download.download = '';
      message.append(download);
      audio.replaceWith(message);
    }, { once: true });
    cell.append(audio);
  }
  function value(row, key) {
    if (key === 'name') return row.nameSimplified || row.name;
    if (key === 'description') return row.descriptionSimplified || row.description || '暂无描述';
    if (key === 'eventName') return row.map === '—' ? row.name : row.map;
    if (key === 'price' && active === 'cards') {
      if (!row.enabled || !row.shopSale) return '不在商店出售';
      return row.shopPrice === null ? '价格未配置' : `${row.shopPrice.toLocaleString('zh-CN')} 点券`;
    }
    return row[key] ?? '—';
  }
  function render() {
    stopAudio();
    const config = pages[active];
    document.title = `${config.label}资料 · 大富翁 Online`;
    $('catalog-table').setAttribute('aria-label', `${config.label}资料`);
    $('catalog-table').dataset.page = active;
    document.querySelector('.table-container').setAttribute('aria-label', `${config.label}资料表，可横向滚动`);
    document.querySelectorAll('#catalog-nav a').forEach((link) => {
      if (link.hash === `#${active}`) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    const heading = element('tr');
    const columns = document.createDocumentFragment();
    config.columns.forEach((column) => {
      const th = element('th', column.label);
      th.scope = 'col';
      heading.append(th);
      const col = element('col');
      col.className = column.column;
      columns.append(col);
    });
    $('table-heading').replaceChildren(heading);
    $('table-columns').replaceChildren(columns);
    if (!Array.isArray(data?.[active])) {
      const row = element('tr');
      const cell = element('td', '资料未能加载，请确认 catalog.js 与本页放在同一文件夹后刷新。');
      cell.colSpan = config.columns.length;
      row.append(cell);
      $('card-list').replaceChildren(row);
      $('pagination').hidden = true;
      return;
    }
    const entries = data[active];
    const pageCount = Math.max(1, Math.ceil(entries.length / pageSize));
    pageIndex = Math.min(pageIndex, pageCount - 1);
    const fragment = document.createDocumentFragment();
    entries.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize).forEach((row) => {
      const tr = element('tr');
      tr.dataset.id = row.id;
      config.columns.forEach((column) => {
        const cell = element('td');
        if (column.type === 'image' || column.type === 'map-image') imageCell(cell, row, column.type === 'map-image');
        else if (column.type === 'audio') audioCell(cell, row);
        else {
          cell.textContent = value(row, column.key);
          if (column.key === 'name' || column.key === 'eventName') cell.className = 'name-cell';
          if (column.key === 'price') cell.className = 'price-cell';
        }
        tr.append(cell);
      });
      fragment.append(tr);
    });
    $('card-list').replaceChildren(fragment);
    $('pagination').hidden = pageCount <= 1;
    $('page-summary').textContent = `共 ${entries.length} 条 · ${pageIndex + 1} / ${pageCount} 页`;
    $('page-number').replaceChildren(...Array.from({ length: pageCount }, (_, index) => {
      const option = element('option', index + 1);
      option.value = index;
      option.selected = index === pageIndex;
      return option;
    }));
    $('previous-page').disabled = pageIndex === 0;
    $('next-page').disabled = pageIndex === pageCount - 1;
  }
  function route() {
    const requested = location.hash.slice(1);
    active = Object.hasOwn(pages, requested) ? requested : 'cards';
    pageIndex = 0;
    render();
    document.querySelector('.table-container').scrollLeft = 0;
    window.scrollTo(0, 0);
  }
  function turnPage(index) {
    pageIndex = index;
    render();
    window.scrollTo(0, 0);
    document.querySelector('.table-container').focus({ preventScroll: true });
  }
  $('previous-page').addEventListener('click', () => turnPage(pageIndex - 1));
  $('next-page').addEventListener('click', () => turnPage(pageIndex + 1));
  $('page-number').addEventListener('change', (event) => turnPage(Number(event.target.value)));
  window.addEventListener('hashchange', route);
  route();
})();
