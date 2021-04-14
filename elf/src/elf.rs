use std::io::{self, Cursor, Read};
use byteorder::{BigEndian, ReadBytesExt, ByteOrder, LittleEndian};
use std::path::Path;
use std::fs::File;

pub struct Elf {
  pub data: Box<[u8]>,
  pub header: ElfHeader,
  pub section_headers: Vec<SectionHeader>,
  pub program_headers: Vec<ProgramHeader>,
}

#[derive(Default)]
pub struct ElfHeader {
  pub identification: ElfIdentification,
  pub description: ElfDescription,
}

#[derive(Default)]
pub struct ElfIdentification {
  pub magic: u32,
  pub class: u8,
  pub endianness: u8,
  pub version: u8,
  pub os_abi: u8,
  pub abi_version: u8,
}

#[derive(Default)]
pub struct ElfDescription {
  pub obj_type: u16,
  pub machine: u16,
  pub version: u32,
  pub entry: u64,
  pub program_hdr_offset: u64,
  pub section_hdr_offset: u64,
  pub flags: u32,
  pub elf_hdr_size: u16,
  pub program_hdr_entry_size: u16,
  pub program_hdr_num: u16,
  pub section_hdr_entry_size: u16,
  pub section_hdr_num: u16,
  pub section_hdr_str_index: u16,
}

#[derive(Default)]
pub struct SectionHeader {
  pub name_index: u32,
  pub section_type: u32,
  pub flags: u64,
  pub address: u64,
  pub offset: u64,
  pub size: u64,
  pub link: u32,
  pub info: u32,
  pub align: u64,
  pub entry_size: u64,
}

#[derive(Default)]
pub struct ProgramHeader {
  pub entry_type: u32,
  pub flags: u32,
  pub offset: u64,
  pub virtual_address: u64,
  pub physical_address: u64,
  pub file_size: u64,
  pub memory_size: u64,
  //ELF32 => flags here
  pub align: u64,
}

impl Elf {
  pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Elf> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    data.shrink_to_fit();
    Ok(Elf::new(data.into_boxed_slice()))
  }

  pub fn new(data: Box<[u8]>) -> Elf {
    let mut elf = Elf {
      data,
      header: Default::default(),
      section_headers: Vec::new(),
      program_headers: Vec::new(),
    };
    elf.load_identification();
    elf.load_description();
    elf.load_section_headers();
    elf.load_program_headers();
    elf
  }

  fn load_identification(&mut self) {
    self.header.identification.magic = BigEndian::read_u32(&self.data[0..4]);
    self.header.identification.class = self.data[4];
    self.header.identification.endianness = self.data[5];
    self.header.identification.version = self.data[6];
    self.header.identification.os_abi = self.data[7];
    self.header.identification.abi_version = self.data[8];
  }

  fn load_description(&mut self) {
    match self.header.identification.endianness {
      1 => self.load_description_with_byteorder::<LittleEndian>(),
      2 => self.load_description_with_byteorder::<BigEndian>(),
      _ => panic!("unknown endianness"),
    };
  }

  fn load_description_with_byteorder<E: ByteOrder>(&mut self) {
    let mut cursor = Cursor::new(&self.data[16..]);
    self.header.description.obj_type = cursor.read_u16::<E>().unwrap();
    self.header.description.machine = cursor.read_u16::<E>().unwrap();
    self.header.description.version = cursor.read_u32::<E>().unwrap();
    match self.header.identification.class {
      1 => {
        self.header.description.entry = cursor.read_u32::<E>().unwrap() as u64;
        self.header.description.program_hdr_offset = cursor.read_u32::<E>().unwrap() as u64;
        self.header.description.section_hdr_offset = cursor.read_u32::<E>().unwrap() as u64;
      },
      2 => {
        self.header.description.entry = cursor.read_u64::<E>().unwrap();
        self.header.description.program_hdr_offset = cursor.read_u64::<E>().unwrap();
        self.header.description.section_hdr_offset = cursor.read_u64::<E>().unwrap();
      },
      _ => panic!("unknown class"),
    };
    self.header.description.flags = cursor.read_u32::<E>().unwrap();
    self.header.description.elf_hdr_size = cursor.read_u16::<E>().unwrap();
    self.header.description.program_hdr_entry_size = cursor.read_u16::<E>().unwrap();
    self.header.description.program_hdr_num = cursor.read_u16::<E>().unwrap();
    self.header.description.section_hdr_entry_size = cursor.read_u16::<E>().unwrap();
    self.header.description.section_hdr_num = cursor.read_u16::<E>().unwrap();
    self.header.description.section_hdr_str_index = cursor.read_u16::<E>().unwrap();
  }

  fn load_section_headers(&mut self) {
    match self.header.identification.endianness {
      1 => self.load_section_headers_with_byteorder::<LittleEndian>(),
      2 => self.load_section_headers_with_byteorder::<BigEndian>(),
      _ => panic!("unknown endianness"),
    };
  }

  fn load_section_headers_with_byteorder<E: ByteOrder>(&mut self) {
    let mut cursor = Cursor::new(&self.data[self.header.description.section_hdr_offset as usize..]);
    for _ in 0..self.header.description.section_hdr_num {
      let mut entry: SectionHeader = Default::default();
      entry.name_index = cursor.read_u32::<E>().unwrap();
      entry.section_type = cursor.read_u32::<E>().unwrap();
      match self.header.identification.class {
        1 => {
          entry.flags = cursor.read_u32::<E>().unwrap() as u64;
          entry.address = cursor.read_u32::<E>().unwrap() as u64;
          entry.offset = cursor.read_u32::<E>().unwrap() as u64;
          entry.size = cursor.read_u32::<E>().unwrap() as u64;
          entry.link = cursor.read_u32::<E>().unwrap();
          entry.info = cursor.read_u32::<E>().unwrap();
          entry.align = cursor.read_u32::<E>().unwrap() as u64;
          entry.entry_size = cursor.read_u32::<E>().unwrap() as u64;
        },
        2 => {
          entry.flags = cursor.read_u64::<E>().unwrap();
          entry.address = cursor.read_u64::<E>().unwrap();
          entry.offset = cursor.read_u64::<E>().unwrap();
          entry.size = cursor.read_u64::<E>().unwrap();
          entry.link = cursor.read_u32::<E>().unwrap();
          entry.info = cursor.read_u32::<E>().unwrap();
          entry.align = cursor.read_u64::<E>().unwrap();
          entry.entry_size = cursor.read_u64::<E>().unwrap();
        },
        _ => panic!("unknown class"),
      };
      self.section_headers.push(entry);
    }
  }

  fn load_program_headers(&mut self) {
    match self.header.identification.endianness {
      1 => self.load_program_headers_with_byteorder::<LittleEndian>(),
      2 => self.load_program_headers_with_byteorder::<BigEndian>(),
      _ => panic!("unknown endianness"),
    };
  }

  fn load_program_headers_with_byteorder<E: ByteOrder>(&mut self) {
    let mut cursor = Cursor::new(&self.data[self.header.description.program_hdr_offset as usize..]);
    for _ in 0..self.header.description.program_hdr_num {
      let mut entry: ProgramHeader = Default::default();
      match self.header.identification.class {
        1 => {
          entry.entry_type = cursor.read_u32::<E>().unwrap();
          entry.offset = cursor.read_u32::<E>().unwrap() as u64;
          entry.virtual_address = cursor.read_u32::<E>().unwrap() as u64;
          entry.physical_address = cursor.read_u32::<E>().unwrap() as u64;
          entry.file_size = cursor.read_u32::<E>().unwrap() as u64;
          entry.memory_size = cursor.read_u32::<E>().unwrap() as u64;
          entry.flags = cursor.read_u32::<E>().unwrap();
          entry.align = cursor.read_u32::<E>().unwrap() as u64;
        },
        2 => {
          entry.entry_type = cursor.read_u32::<E>().unwrap();
          entry.flags = cursor.read_u32::<E>().unwrap();
          entry.offset = cursor.read_u64::<E>().unwrap();
          entry.virtual_address = cursor.read_u64::<E>().unwrap();
          entry.physical_address = cursor.read_u64::<E>().unwrap();
          entry.file_size = cursor.read_u64::<E>().unwrap();
          entry.memory_size = cursor.read_u64::<E>().unwrap();
          entry.align = cursor.read_u64::<E>().unwrap();
        },
        _ => panic!("unknown class"),
      };
      self.program_headers.push(entry);
    }
  }
}
