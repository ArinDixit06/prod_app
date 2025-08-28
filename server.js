const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://blacandand:hTxALYpdCJVorrDN@users.clitnk5.mongodb.net/prod', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User Model
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', UserSchema);

// Todo Model
const TodoSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
  },
  dueDate: {
    type: Date,
  },
  completed: {
    type: Boolean,
    default: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Todo = mongoose.model('Todo', TodoSchema);

// Note Model
const NoteSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Note = mongoose.model('Note', NoteSchema);

// CalendarTask Model
const CalendarTaskSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
  },
  startTime: {
    type: Date,
    required: true,
  },
  endTime: {
    type: Date,
    required: true,
  },
  allDay: {
    type: Boolean,
    default: false,
  },
  location: {
    type: String,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const CalendarTask = mongoose.model('CalendarTask', CalendarTaskSchema);

// JWT Secret
const jwtSecret = process.env.JWT_SECRET || 'supersecretjwtkey';

// Auth Middleware
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, jwtSecret);
      req.user = await User.findById(decoded.id).select('-password');
      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ msg: 'Not authorized, token failed' });
    }
  }
  if (!token) {
    res.status(401).json({ msg: 'Not authorized, no token' });
  }
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ msg: 'User already exists' });
    }
    const user = await User.create({ email, password });
    res.status(201).json({
      _id: user._id,
      email: user.email,
      token: jwt.sign({ id: user._id }, jwtSecret, { expiresIn: '1h' }),
    });
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && (await user.matchPassword(password))) {
      res.json({
        _id: user._id,
        email: user.email,
        token: jwt.sign({ id: user._id }, jwtSecret, { expiresIn: '1h' }),
      });
    } else {
      res.status(401).json({ msg: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

// Todo Routes
app.get('/api/todos', protect, async (req, res) => {
  try {
    const todos = await Todo.find({ user: req.user._id });
    res.json(todos);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.post('/api/todos', protect, async (req, res) => {
  const { title, description, dueDate, completed } = req.body;
  try {
    const todo = await Todo.create({
      user: req.user._id,
      title,
      description,
      dueDate,
      completed,
    });
    res.status(201).json(todo);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.put('/api/todos/:id', protect, async (req, res) => {
  const { title, description, dueDate, completed } = req.body;
  try {
    let todo = await Todo.findById(req.params.id);
    if (!todo || todo.user.toString() !== req.user._id.toString()) {
      return res.status(404).json({ msg: 'Todo not found or unauthorized' });
    }
    todo.title = title || todo.title;
    todo.description = description || todo.description;
    todo.dueDate = dueDate || todo.dueDate;
    todo.completed = completed !== undefined ? completed : todo.completed;
    todo.updatedAt = Date.now();
    await todo.save();
    res.json(todo);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.delete('/api/todos/:id', protect, async (req, res) => {
  try {
    const todo = await Todo.findById(req.params.id);
    if (!todo || todo.user.toString() !== req.user._id.toString()) {
      return res.status(404).json({ msg: 'Todo not found or unauthorized' });
    }
    await Todo.deleteOne({ _id: req.params.id });
    res.json({ msg: 'Todo removed' });
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

// Note Routes
app.get('/api/notes', protect, async (req, res) => {
  try {
    const notes = await Note.find({ user: req.user._id });
    res.json(notes);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.post('/api/notes', protect, async (req, res) => {
  const { title, content } = req.body;
  try {
    const note = await Note.create({
      user: req.user._id,
      title,
      content,
    });
    res.status(201).json(note);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.put('/api/notes/:id', protect, async (req, res) => {
  const { title, content } = req.body;
  try {
    let note = await Note.findById(req.params.id);
    if (!note || note.user.toString() !== req.user._id.toString()) {
      return res.status(404).json({ msg: 'Note not found or unauthorized' });
    }
    note.title = title || note.title;
    note.content = content || note.content;
    note.updatedAt = Date.now();
    await note.save();
    res.json(note);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.delete('/api/notes/:id', protect, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note || note.user.toString() !== req.user._id.toString()) {
      return res.status(404).json({ msg: 'Note not found or unauthorized' });
    }
    await Note.deleteOne({ _id: req.params.id });
    res.json({ msg: 'Note removed' });
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

// Calendar Task Routes
app.get('/api/calendar-tasks', protect, async (req, res) => {
  try {
    const calendarTasks = await CalendarTask.find({ user: req.user._id });
    res.json(calendarTasks);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.post('/api/calendar-tasks', protect, async (req, res) => {
  const { title, description, startTime, endTime, allDay, location } = req.body;
  try {
    const calendarTask = await CalendarTask.create({
      user: req.user._id,
      title,
      description,
      startTime,
      endTime,
      allDay,
      location,
    });
    res.status(201).json(calendarTask);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.put('/api/calendar-tasks/:id', protect, async (req, res) => {
  const { title, description, startTime, endTime, allDay, location } = req.body;
  try {
    let calendarTask = await CalendarTask.findById(req.params.id);
    if (!calendarTask || calendarTask.user.toString() !== req.user._id.toString()) {
      return res.status(404).json({ msg: 'Calendar task not found or unauthorized' });
    }
    calendarTask.title = title || calendarTask.title;
    calendarTask.description = description || calendarTask.description;
    calendarTask.startTime = startTime || calendarTask.startTime;
    calendarTask.endTime = endTime || calendarTask.endTime;
    calendarTask.allDay = allDay !== undefined ? allDay : calendarTask.allDay;
    calendarTask.location = location || calendarTask.location;
    calendarTask.updatedAt = Date.now();
    await calendarTask.save();
    res.json(calendarTask);
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

app.delete('/api/calendar-tasks/:id', protect, async (req, res) => {
  try {
    const calendarTask = await CalendarTask.findById(req.params.id);
    if (!calendarTask || calendarTask.user.toString() !== req.user._id.toString()) {
      return res.status(404).json({ msg: 'Calendar task not found or unauthorized' });
    }
    await CalendarTask.deleteOne({ _id: req.params.id });
    res.json({ msg: 'Calendar task removed' });
  } catch (error) {
    res.status(500).json({ msg: 'Server error', error: error.message });
  }
});

// Sync Route (from original server.js)
app.post('/api/sync', async (req, res) => {
  const { userId, todos, notes, calendarTasks } = req.body;

  if (!userId) {
    return res.status(400).json({ msg: 'User ID is required for sync operations.' });
  }

  const syncCollection = async (items, Model) => {
    const results = [];
    for (const item of items) {
      try {
        item.user = userId;

        if (item._id) {
          const existingItem = await Model.findById(item._id);
          if (existingItem) {
            if (new Date(item.updatedAt) > new Date(existingItem.updatedAt)) {
              const updated = await Model.findByIdAndUpdate(item._id, item, { new: true, runValidators: true });
              results.push(updated);
            } else {
              results.push(existingItem);
            }
          } else {
            const newItem = await Model.create(item);
            results.push(newItem);
          }
        } else {
          const newItem = await Model.create(item);
          results.push(newItem);
        }
      } catch (error) {
        console.error(`Error syncing ${Model.modelName} item:`, error);
        results.push({ _id: item._id, error: error.message, status: 'failed' });
      }
    }
    return results;
  };

  try {
    const syncedTodos = await syncCollection(todos || [], Todo);
    const syncedNotes = await syncCollection(notes || [], Note);
    const syncedCalendarTasks = await syncCollection(calendarTasks || [], CalendarTask);

    const allTodos = await Todo.find({ user: userId });
    const allNotes = await Note.find({ user: userId });
    const allCalendarTasks = await CalendarTask.find({ user: userId });

    res.status(200).json({
      msg: 'Sync completed successfully',
      todos: allTodos,
      notes: allNotes,
      calendarTasks: allCalendarTasks,
    });
  } catch (error) {
    console.error('Full sync failed:', error);
    res.status(500).json({ msg: 'Server error during sync', error: error.message });
  }
});

app.get('/', (req, res) => {
  res.send('API is running...');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
